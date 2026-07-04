require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const User = require('./models/User');
const { isValidGmail } = require('./utils/validateEmail');
const { generateOTP } = require('./utils/otp');
const { sendOTPEmail } = require('./utils/sendEmail');

const app = express();
const PORT = process.env.PORT || 3000;

const OTP_TTL_MS = 5 * 60 * 1000;
const RESEND_COOLDOWN_MS = 60 * 1000;
const MAX_OTP_ATTEMPTS = 5;

// ── CORS ──────────────────────────────────────────────────────
const rawOrigin = (process.env.CLIENT_ORIGIN || '').replace(/\/$/, '');

app.use(cors({
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        if (!rawOrigin) return callback(null, true);
        if (origin.replace(/\/$/, '') === rawOrigin) return callback(null, true);
        return callback(new Error('Not allowed by CORS'));
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
}));
app.options('*', cors());
app.use(express.json());

app.get('/', (req, res) => {
    res.json({ status: 'PLC SimTel Auth Server running', time: new Date() });
});

// ── MongoDB (cached for serverless) ───────────────────────────
let isConnected = false;

async function connectDB() {
    if (isConnected && mongoose.connection.readyState === 1) return;
    const rawUri = process.env.MONGODB_URI;
    const mongoUri = rawUri.includes('/?')
        ? rawUri.replace('/?', '/plc-simtel-auth?')
        : rawUri;
    await mongoose.connect(mongoUri, {
        serverSelectionTimeoutMS: 5000,
        socketTimeoutMS: 20000,
        maxPoolSize: 5,
        bufferCommands: false
    });
    isConnected = true;
    console.log('MongoDB connected');
}

const withDB = (fn) => async (req, res) => {
    try {
        await connectDB();
        return fn(req, res);
    } catch (err) {
        console.error('DB connection error:', err.message);
        return res.status(500).json({ success: false, message: 'Database connection failed', debug: err.message });
    }
};

// ── Helpers ────────────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'change-in-production';

const signToken = (user) => jwt.sign(
    { id: user._id, email: user.email, role: user.role, name: user.name },
    JWT_SECRET,
    { expiresIn: '7d' }
);

const authMiddleware = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer '))
        return res.status(401).json({ success: false, message: 'No token provided' });
    try {
        req.user = jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
        next();
    } catch {
        return res.status(401).json({ success: false, message: 'Invalid or expired token' });
    }
};

const adminMiddleware = (req, res, next) => {
    if (req.user.role !== 'admin')
        return res.status(403).json({ success: false, message: 'Admin access required' });
    next();
};

// Shared OTP issuing logic - used by both self-register and admin-create.
async function issueOtp(user) {
    if (user.otpLastSentAt && (Date.now() - user.otpLastSentAt.getTime()) < RESEND_COOLDOWN_MS) {
        const waitSeconds = Math.ceil((RESEND_COOLDOWN_MS - (Date.now() - user.otpLastSentAt.getTime())) / 1000);
        const err = new Error(`Please wait ${waitSeconds}s before requesting another code.`);
        err.code = 'COOLDOWN';
        throw err;
    }

    const rawOtp = generateOTP();
    user.otp = await bcrypt.hash(rawOtp, 10);
    user.otpExpires = new Date(Date.now() + OTP_TTL_MS);
    user.otpAttempts = 0;
    user.otpLastSentAt = new Date();
    await user.save();

    await sendOTPEmail(user.email, rawOtp, user.name);
}

// ══════════════════════════════════════════════════════════════
//  AUTH ROUTES
// ══════════════════════════════════════════════════════════════

// Self-registration: needs OTP verification AND admin approval before login.
// FIX: If email exists but is NOT verified, resend OTP instead of blocking.
app.post('/api/auth/register', withDB(async (req, res) => {
    let createdUser = null;
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password)
            return res.status(400).json({ success: false, message: 'Name, email and password are required' });
        if (password.length < 6)
            return res.status(400).json({ success: false, message: 'Password must be at least 6 characters' });

        const normalizedEmail = email.trim().toLowerCase();

        if (!isValidGmail(normalizedEmail)) {
            return res.status(400).json({ success: false, message: 'Only real @gmail.com addresses are allowed.' });
        }

        // ── FIX: If user exists but isn't verified, resend OTP ──
        const existing = await User.findOne({ email: normalizedEmail });
        if (existing) {
            if (existing.emailVerified) {
                // Fully verified user — can't re-register
                return res.status(409).json({
                    success: false,
                    message: 'Email already registered and verified. Please log in instead.',
                    alreadyVerified: true
                });
            }
            // Unverified user — resend OTP so they aren't stuck
            console.log(`Re-sending OTP for existing unverified user: ${normalizedEmail}`);
            await issueOtp(existing);
            return res.status(200).json({
                success: true,
                message: 'A new verification code has been sent to your email.',
                redirectTo: 'verify-otp',
                email: normalizedEmail
            });
        }

        // ── New user: create and send OTP ──
        const hashed = await bcrypt.hash(password, 12);
        createdUser = await User.create({
            name, email: normalizedEmail, password: hashed,
            isActive: false, emailVerified: false, registrationSource: 'self'
        });

        await issueOtp(createdUser);

        res.status(201).json({
            success: true,
            message: 'Registration successful! Check your email for a verification code.',
            redirectTo: 'verify-otp',
            email: normalizedEmail
        });
    } catch (err) {
        console.error('Register error:', err.message);
        if (createdUser) await User.findByIdAndDelete(createdUser._id).catch(() => {});
        if (err.name === 'ValidationError') {
            return res.status(400).json({ success: false, message: Object.values(err.errors)[0].message });
        }
        res.status(500).json({ success: false, message: 'Could not complete registration. Please try again.', debug: err.message });
    }
}));

app.post('/api/auth/login', withDB(async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password)
            return res.status(400).json({ success: false, message: 'Email and password required' });

        const normalizedEmail = email.trim().toLowerCase();
        const user = await User.findOne({ email: normalizedEmail });
        if (!user || !(await bcrypt.compare(password, user.password)))
            return res.status(401).json({ success: false, message: 'Invalid email or password' });

        if (!user.emailVerified)
            return res.status(403).json({ success: false, message: 'Please verify your email with the code sent to you before logging in.', needsVerification: true, email: normalizedEmail });
        if (!user.isActive)
            return res.status(403).json({ success: false, message: 'Your email is verified, but your account is still pending admin approval.' });

        user.lastLogin = new Date();
        await user.save();

        res.json({
            success: true,
            token: signToken(user),
            user: { name: user.name, email: user.email, role: user.role, apps: user.apps }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
}));

app.get('/api/auth/verify', authMiddleware, withDB(async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password -otp');
        if (!user || !user.isActive || !user.emailVerified)
            return res.status(403).json({ success: false, message: 'Access revoked' });
        res.json({ success: true, user: { name: user.name, email: user.email, role: user.role, apps: user.apps } });
    } catch {
        res.status(500).json({ success: false, message: 'Server error' });
    }
}));

app.post('/api/auth/logout', authMiddleware, (req, res) => {
    res.json({ success: true, message: 'Logged out' });
});

// ── OTP verify / resend - PUBLIC, called by the user themself ─────
app.post('/api/auth/verify-otp', withDB(async (req, res) => {
    try {
        const { email, otp } = req.body;
        if (!email || !otp) return res.status(400).json({ success: false, message: 'Email and OTP are required.' });

        const normalizedEmail = email.trim().toLowerCase();
        const user = await User.findOne({ email: normalizedEmail });

        if (!user) return res.status(404).json({ success: false, message: 'No account found with this email.' });
        if (user.emailVerified) return res.status(400).json({ success: false, message: 'This email is already verified.' });
        if (!user.otp || !user.otpExpires || user.otpExpires < new Date()) {
            return res.status(400).json({ success: false, message: 'This code has expired. Please request a new one.' });
        }
        if (user.otpAttempts >= MAX_OTP_ATTEMPTS) {
            return res.status(429).json({ success: false, message: 'Too many incorrect attempts. Please request a new code.' });
        }

        const match = await bcrypt.compare(otp, user.otp);
        if (!match) {
            user.otpAttempts += 1;
            await user.save();
            const remaining = MAX_OTP_ATTEMPTS - user.otpAttempts;
            return res.status(400).json({ success: false, message: `Incorrect code. ${remaining} attempt(s) remaining.` });
        }

        user.emailVerified = true;
        user.otp = null;
        user.otpExpires = null;
        user.otpAttempts = 0;

        // Admin-created accounts are already vetted - auto-approve on verify.
        // Self-registered accounts still need explicit admin approval.
        if (user.registrationSource === 'admin') {
            user.isActive = true;
        }
        await user.save();

        const message = user.isActive
            ? 'Email verified! You can now log in.'
            : 'Email verified! Your account is now pending admin approval before you can log in.';

        res.json({ success: true, message });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error while verifying code.' });
    }
}));

app.post('/api/auth/resend-otp', withDB(async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ success: false, message: 'Email is required.' });

        const normalizedEmail = email.trim().toLowerCase();
        const user = await User.findOne({ email: normalizedEmail });

        if (!user) return res.status(404).json({ success: false, message: 'No account found with this email.' });
        if (user.emailVerified) return res.status(400).json({ success: false, message: 'This email is already verified.' });

        await issueOtp(user);
        res.json({ success: true, message: 'A new code has been sent to your email.' });
    } catch (err) {
        if (err.code === 'COOLDOWN') {
            return res.status(429).json({ success: false, message: err.message });
        }
        console.error(err);
        res.status(500).json({ success: false, message: 'Could not resend code. Please try again.', debug: err.message });
    }
}));

// ══════════════════════════════════════════════════════════════
//  ADMIN ROUTES
// ══════════════════════════════════════════════════════════════

app.post('/api/admin/make-admin', withDB(async (req, res) => {
    try {
        const { email, adminSecret } = req.body;
        if (adminSecret !== (process.env.ADMIN_SECRET || 'scientech-admin-2024'))
            return res.status(403).json({ success: false, message: 'Invalid admin secret' });

        const user = await User.findOneAndUpdate(
            { email: (email || '').trim().toLowerCase() },
            { role: 'admin', isActive: true, emailVerified: true },
            { new: true }
        );
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        res.json({ success: true, message: `${email} is now an admin` });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
}));

app.get('/api/admin/users', authMiddleware, adminMiddleware, withDB(async (req, res) => {
    try {
        const users = await User.find({}).select('-password -otp').sort({ createdAt: -1 });
        res.json({ success: true, users });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
}));

// Admin creates the account - stays inactive until the USER verifies via OTP,
// then auto-activates since an admin already vetted this account by creating it.
app.post('/api/admin/users', authMiddleware, adminMiddleware, withDB(async (req, res) => {
    let createdUser = null;
    try {
        const { name, email, password, role } = req.body;
        if (!name || !email || !password)
            return res.status(400).json({ success: false, message: 'Name, email and password required' });
        if (password.length < 6)
            return res.status(400).json({ success: false, message: 'Password must be at least 6 characters.' });

        const normalizedEmail = email.trim().toLowerCase();

        if (!isValidGmail(normalizedEmail)) {
            return res.status(400).json({ success: false, message: 'Only real @gmail.com addresses are allowed.' });
        }
        if (await User.findOne({ email: normalizedEmail })) {
            return res.status(409).json({ success: false, message: 'Email already registered' });
        }

        const hashed = await bcrypt.hash(password, 12);
        createdUser = await User.create({
            name, email: normalizedEmail, password: hashed, role: role || 'user',
            isActive: false, emailVerified: false, registrationSource: 'admin'
        });

        await issueOtp(createdUser);

        res.status(201).json({
            success: true,
            message: 'User created. A verification code has been emailed to them - once they verify it, their account activates automatically.',
            user: { _id: createdUser._id, name: createdUser.name, email: createdUser.email, role: createdUser.role, isActive: createdUser.isActive }
        });
    } catch (err) {
        console.error(err);
        if (createdUser) await User.findByIdAndDelete(createdUser._id).catch(() => {});
        if (err.name === 'ValidationError') {
            return res.status(400).json({ success: false, message: Object.values(err.errors)[0].message });
        }
        res.status(500).json({ success: false, message: 'Could not create user. Please check the email and try again.', debug: err.message });
    }
}));

app.put('/api/admin/users/:id/activate', authMiddleware, adminMiddleware, withDB(async (req, res) => {
    try {
        const user = await User.findByIdAndUpdate(req.params.id, { isActive: true }, { new: true }).select('-password -otp');
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        res.json({ success: true, message: `${user.name} activated`, user });
    } catch (err) { console.error(err); res.status(500).json({ success: false, message: 'Server error' }); }
}));

app.put('/api/admin/users/:id/deactivate', authMiddleware, adminMiddleware, withDB(async (req, res) => {
    try {
        const user = await User.findByIdAndUpdate(req.params.id, { isActive: false }, { new: true }).select('-password -otp');
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        res.json({ success: true, message: `${user.name} deactivated`, user });
    } catch (err) { console.error(err); res.status(500).json({ success: false, message: 'Server error' }); }
}));

app.put('/api/admin/users/:id/role', authMiddleware, adminMiddleware, withDB(async (req, res) => {
    try {
        const { role } = req.body;
        if (!['user', 'admin'].includes(role))
            return res.status(400).json({ success: false, message: 'Role must be user or admin' });
        const user = await User.findByIdAndUpdate(req.params.id, { role }, { new: true }).select('-password -otp');
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        res.json({ success: true, message: `${user.name} role set to ${role}`, user });
    } catch (err) { console.error(err); res.status(500).json({ success: false, message: 'Server error' }); }
}));

app.delete('/api/admin/users/:id', authMiddleware, adminMiddleware, withDB(async (req, res) => {
    try {
        const user = await User.findByIdAndDelete(req.params.id);
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        res.json({ success: true, message: `${user.name} deleted` });
    } catch (err) { console.error(err); res.status(500).json({ success: false, message: 'Server error' }); }
}));

// ── Start: works locally AND exports for Vercel ───────────────
if (require.main === module) {
    connectDB().then(() => {
        app.listen(PORT, () => console.log(`Auth server running on port ${PORT}`));
    }).catch(err => {
        console.error('Failed to connect to MongoDB:', err.message);
        process.exit(1);
    });
} else {
    module.exports = app;
}