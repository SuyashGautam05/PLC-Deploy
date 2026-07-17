require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const cors = require('cors');

const User = require('./models/User');
const Progress = require('./models/Progress');
const College = require('./models/College');
const { isValidGmail } = require('./utils/validateEmail');
const { generateOTP } = require('./utils/otp');
const { sendOTPEmail } = require('./utils/sendEmail');

const app = express();
const PORT = process.env.PORT || 3000;

const OTP_TTL_MS = 5 * 60 * 1000;
const RESEND_COOLDOWN_MS = 60 * 1000;
const MAX_OTP_ATTEMPTS = 5;

// A login session (and the license seat it holds, if any) is valid for this
// long. If the user never logs out, the seat auto-frees after this window
// instead of being stuck forever - important for shared/lab PCs.
const SESSION_TTL_STR = '12h';
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;

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

const signToken = (user, sid) => jwt.sign(
    { id: user._id, email: user.email, role: user.role, name: user.name, sid },
    JWT_SECRET,
    { expiresIn: SESSION_TTL_STR }
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

// Releases the license seat a user's session was holding (if their college
// is under a license limit) and clears activeSession. Safe to call even if
// the user has no college license or no active session - it's a no-op then.
// Does NOT save the user document - caller is responsible for that.
async function releaseSeat(user) {
    if (user.collegeKey) {
        await College.updateOne(
            { nameKey: user.collegeKey, activeCount: { $gt: 0 } },
            { $inc: { activeCount: -1 } }
        );
    }
    user.activeSession = { token: null, loginAt: null, expiresAt: null, userAgent: '' };
}

// After a college's licenseLimit is lowered (or activeCount somehow drifts
// above it), force-logs-out the least-recently-logged-in users from that
// college until activeCount is back within licenseLimit. This is what makes
// "excess users get automatically logged out" actually happen when an admin
// tightens a license, rather than just blocking future logins.
async function reconcileCollegeSeats(college) {
    let excess = college.activeCount - college.licenseLimit;
    if (excess <= 0) return 0;

    const usersToKick = await User.find({
        collegeKey: college.nameKey,
        'activeSession.token': { $ne: null }
    }).sort({ 'activeSession.loginAt': 1 }).limit(excess);

    for (const u of usersToKick) {
        u.activeSession = { token: null, loginAt: null, expiresAt: null, userAgent: '' };
        await u.save();
    }

    if (usersToKick.length > 0) {
        await College.updateOne(
            { _id: college._id },
            { $inc: { activeCount: -usersToKick.length } }
        );
    }
    return usersToKick.length;
}

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
app.post('/api/auth/register', withDB(async (req, res) => {
    let createdUser = null;
    try {
        const { name, email, password, college } = req.body;
        if (!name || !email || !password || !college)
            return res.status(400).json({ success: false, message: 'Name, email, password and college are required' });
        if (password.length < 6)
            return res.status(400).json({ success: false, message: 'Password must be at least 6 characters' });
        if (college.trim().length < 2)
            return res.status(400).json({ success: false, message: 'Please enter a valid college/institute name' });

        const normalizedEmail = email.trim().toLowerCase();

        if (!isValidGmail(normalizedEmail)) {
            return res.status(400).json({ success: false, message: 'Only real @gmail.com addresses are allowed.' });
        }
        if (await User.findOne({ email: normalizedEmail })) {
            return res.status(409).json({ success: false, message: 'Email already registered' });
        }

        const hashed = await bcrypt.hash(password, 12);
        createdUser = await User.create({
            name, email: normalizedEmail, password: hashed, college: college.trim(),
            isActive: false, emailVerified: false, registrationSource: 'self'
        });

        await issueOtp(createdUser);

        res.status(201).json({
            success: true,
            message: 'Registration successful! Check your email for a verification code.'
        });
    } catch (err) {
        console.error(err);
        if (createdUser) await User.findByIdAndDelete(createdUser._id).catch(() => {});
        if (err.name === 'ValidationError') {
            return res.status(400).json({ success: false, message: Object.values(err.errors)[0].message });
        }
        res.status(500).json({ success: false, message: 'Could not complete registration. Please check the email and try again.', debug: err.message });
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
            return res.status(403).json({ success: false, message: 'Please verify your email with the code sent to you before logging in.' });
        if (!user.isActive)
            return res.status(403).json({ success: false, message: 'Your email is verified, but your account is still pending admin approval.' });

        const now = new Date();

        // ── One active login per account ──────────────────────────
        const session = user.activeSession;
        if (session && session.token) {
            if (session.expiresAt && session.expiresAt > now) {
                // Genuinely still logged in elsewhere - refuse this login.
                return res.status(409).json({
                    success: false,
                    message: 'This account is already logged in on another device or browser. Please log out there first, or contact your admin if you think this is a mistake.'
                });
            }
            // The old session token is past its expiry - it was never
            // properly logged out (e.g. tab closed on a lab PC). Reclaim
            // the seat it was holding before continuing.
            await releaseSeat(user);
        }

        // ── License seat check (only applies if this college has a
        //    licensed seat limit configured by the admin) ───────────
        let reservedCollege = null;
        if (user.collegeKey) {
            const college = await College.findOne({ nameKey: user.collegeKey });
            if (college) {
                reservedCollege = await College.findOneAndUpdate(
                    { nameKey: user.collegeKey, $expr: { $lt: ['$activeCount', '$licenseLimit'] } },
                    { $inc: { activeCount: 1 } },
                    { new: true }
                );
                if (!reservedCollege) {
                    return res.status(403).json({
                        success: false,
                        message: `${college.name} has reached its licensed limit of ${college.licenseLimit} simultaneous users. Please try again once a seat frees up, or contact your admin.`
                    });
                }
            }
        }

        const sid = crypto.randomBytes(16).toString('hex');
        user.activeSession = {
            token: sid,
            loginAt: now,
            expiresAt: new Date(now.getTime() + SESSION_TTL_MS),
            userAgent: (req.headers['user-agent'] || '').slice(0, 200)
        };
        user.lastLogin = now;

        try {
            await user.save();
        } catch (saveErr) {
            // Roll back the seat reservation if we couldn't actually log the user in.
            if (reservedCollege) {
                await College.updateOne({ _id: reservedCollege._id }, { $inc: { activeCount: -1 } });
            }
            throw saveErr;
        }

        res.json({
            success: true,
            token: signToken(user, sid),
            user: { name: user.name, email: user.email, role: user.role, college: user.college, apps: user.apps }
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

        const session = user.activeSession;
        if (!session || session.token !== req.user.sid) {
            // Someone else logged into this account (or an admin force-logged
            // this session out) - this particular token is no longer valid.
            return res.status(401).json({ success: false, message: 'You have been logged out because this account was signed in elsewhere.' });
        }
        if (!session.expiresAt || session.expiresAt < new Date()) {
            // This is still the recorded session, but its window has lapsed -
            // reclaim the seat it was holding and end it cleanly.
            await releaseSeat(user);
            await user.save();
            return res.status(401).json({ success: false, message: 'Your session has expired. Please log in again.' });
        }

        res.json({ success: true, user: { name: user.name, email: user.email, role: user.role, college: user.college, apps: user.apps } });
    } catch {
        res.status(500).json({ success: false, message: 'Server error' });
    }
}));

app.post('/api/auth/logout', authMiddleware, withDB(async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        // Only release the seat if this request's token is the one currently
        // on file - stops a stale/second tab's logout call from wiping out a
        // newer, legitimately active session.
        if (user && user.activeSession && user.activeSession.token === req.user.sid) {
            await releaseSeat(user);
            await user.save();
        }
        res.json({ success: true, message: 'Logged out' });
    } catch (err) {
        console.error(err);
        res.json({ success: true, message: 'Logged out' });
    }
}));

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
        const users = await User.find({}).select('-password -otp -activeSession.token').sort({ createdAt: -1 });
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
        const { name, email, password, role, college } = req.body;
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
            college: (college || '').trim(),
            isActive: false, emailVerified: false, registrationSource: 'admin'
        });

        await issueOtp(createdUser);

        res.status(201).json({
            success: true,
            message: 'User created. A verification code has been emailed to them - once they verify it, their account activates automatically.',
            user: { _id: createdUser._id, name: createdUser.name, email: createdUser.email, role: createdUser.role, college: createdUser.college, isActive: createdUser.isActive }
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
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        user.isActive = false;
        if (user.activeSession && user.activeSession.token) await releaseSeat(user);
        await user.save();
        const safeUser = await User.findById(user._id).select('-password -otp -activeSession.token');
        res.json({ success: true, message: `${user.name} deactivated`, user: safeUser });
    } catch (err) { console.error(err); res.status(500).json({ success: false, message: 'Server error' }); }
}));

// Lets an admin fix/assign a user's college (e.g. legacy accounts created
// before this field existed, or typo corrections) so grouping in the
// admin panel - and license-seat matching - stay accurate.
app.put('/api/admin/users/:id/college', authMiddleware, adminMiddleware, withDB(async (req, res) => {
    try {
        const { college } = req.body;
        if (typeof college !== 'string' || college.trim().length < 2) {
            return res.status(400).json({ success: false, message: 'Please provide a valid college/institute name.' });
        }
        // Fetch + save (not findByIdAndUpdate) so the pre-save hook that
        // derives collegeKey actually runs.
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        user.college = college.trim();
        await user.save();
        const safeUser = await User.findById(user._id).select('-password -otp -activeSession.token');
        res.json({ success: true, message: `${user.name}'s college updated`, user: safeUser });
    } catch (err) { console.error(err); res.status(500).json({ success: false, message: 'Server error' }); }
}));

// Admin can force-end a user's current session, freeing up their license
// seat immediately - e.g. they forgot to log out on a shared lab PC.
app.put('/api/admin/users/:id/force-logout', authMiddleware, adminMiddleware, withDB(async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        if (!user.activeSession || !user.activeSession.token) {
            return res.status(400).json({ success: false, message: `${user.name} is not currently logged in.` });
        }
        await releaseSeat(user);
        await user.save();
        res.json({ success: true, message: `${user.name} has been logged out and their seat freed.` });
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
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        if (user.activeSession && user.activeSession.token) {
            await releaseSeat(user);
        }
        await User.findByIdAndDelete(req.params.id);
        res.json({ success: true, message: `${user.name} deleted` });
    } catch (err) { console.error(err); res.status(500).json({ success: false, message: 'Server error' }); }
}));

// ══════════════════════════════════════════════════════════════
//  COLLEGE LICENSE ROUTES
// ══════════════════════════════════════════════════════════════

// GET all licensed colleges, each annotated with how many registered users
// currently point at that college (regardless of whether they're online).
app.get('/api/admin/colleges', authMiddleware, adminMiddleware, withDB(async (req, res) => {
    try {
        const colleges = await College.find({}).sort({ name: 1 });
        const counts = await User.aggregate([
            { $match: { collegeKey: { $ne: '' } } },
            { $group: { _id: '$collegeKey', count: { $sum: 1 } } }
        ]);
        const countMap = Object.fromEntries(counts.map(c => [c._id, c.count]));
        const enriched = colleges.map(c => ({ ...c.toObject(), registeredUsers: countMap[c.nameKey] || 0 }));
        res.json({ success: true, colleges: enriched });
    } catch (err) { console.error(err); res.status(500).json({ success: false, message: 'Server error' }); }
}));

// POST create a new license record for a college/company.
app.post('/api/admin/colleges', authMiddleware, adminMiddleware, withDB(async (req, res) => {
    try {
        const { name, licenseLimit, contactEmail, notes } = req.body;
        if (!name || name.trim().length < 2) {
            return res.status(400).json({ success: false, message: 'Please provide a valid college/company name.' });
        }
        const limit = parseInt(licenseLimit, 10);
        if (!Number.isInteger(limit) || limit < 1) {
            return res.status(400).json({ success: false, message: 'License limit must be a whole number of at least 1.' });
        }
        const nameKey = name.trim().toLowerCase();
        if (await College.findOne({ nameKey })) {
            return res.status(409).json({ success: false, message: 'A license already exists for this college. Edit it instead.' });
        }
        const college = await College.create({
            name: name.trim(), nameKey, licenseLimit: limit,
            contactEmail: (contactEmail || '').trim(), notes: (notes || '').trim()
        });
        res.status(201).json({ success: true, message: `License created for ${college.name}`, college });
    } catch (err) { console.error(err); res.status(500).json({ success: false, message: 'Server error' }); }
}));

// PUT update a college's license limit / name / contact / notes. If the new
// limit is lower than the current active count, the least-recently-logged-in
// excess users are automatically force-logged-out to bring it back in line.
app.put('/api/admin/colleges/:id', authMiddleware, adminMiddleware, withDB(async (req, res) => {
    try {
        const { name, licenseLimit, contactEmail, notes } = req.body;
        const college = await College.findById(req.params.id);
        if (!college) return res.status(404).json({ success: false, message: 'License not found' });

        if (name && name.trim().length >= 2) {
            college.name = name.trim();
            college.nameKey = name.trim().toLowerCase();
        }
        if (licenseLimit !== undefined) {
            const limit = parseInt(licenseLimit, 10);
            if (!Number.isInteger(limit) || limit < 1) {
                return res.status(400).json({ success: false, message: 'License limit must be a whole number of at least 1.' });
            }
            college.licenseLimit = limit;
        }
        if (contactEmail !== undefined) college.contactEmail = contactEmail.trim();
        if (notes !== undefined) college.notes = notes.trim();

        try {
            await college.save();
        } catch (saveErr) {
            if (saveErr.code === 11000) {
                return res.status(409).json({ success: false, message: 'Another license already uses that college name.' });
            }
            throw saveErr;
        }

        const kicked = await reconcileCollegeSeats(college);
        const refreshed = await College.findById(college._id);

        res.json({
            success: true,
            message: kicked > 0
                ? `License updated. ${kicked} user(s) over the new limit were automatically logged out to free up seats.`
                : 'License updated.',
            college: refreshed
        });
    } catch (err) { console.error(err); res.status(500).json({ success: false, message: 'Server error' }); }
}));

// DELETE removes a college's license record entirely - its users become
// unrestricted (unlimited concurrent logins) again, same as any college
// that was never licensed. Does not touch any currently active sessions.
app.delete('/api/admin/colleges/:id', authMiddleware, adminMiddleware, withDB(async (req, res) => {
    try {
        const college = await College.findByIdAndDelete(req.params.id);
        if (!college) return res.status(404).json({ success: false, message: 'License not found' });
        res.json({ success: true, message: `License removed for ${college.name}` });
    } catch (err) { console.error(err); res.status(500).json({ success: false, message: 'Server error' }); }
}));

// ══════════════════════════════════════════════════════════════
//  PROGRESS TRACKING ROUTES (which topics a user has read)
// ══════════════════════════════════════════════════════════════

// POST /api/progress/mark-read   body: { topicId, topicTitle, topicUrl, sectionTitle }
// Called from index.html the moment a topic is opened in the popup.
app.post('/api/progress/mark-read', authMiddleware, withDB(async (req, res) => {
    try {
        const { topicId, topicTitle, topicUrl, sectionTitle, appId } = req.body;
        if (!topicId) {
            return res.status(400).json({ success: false, message: 'topicId is required.' });
        }

        const now = new Date();
        const progress = await Progress.findOneAndUpdate(
            { user: req.user.id, topicId },
            {
                $set: {
                    topicTitle: topicTitle || '',
                    topicUrl: topicUrl || topicId,
                    sectionTitle: sectionTitle || '',
                    appId: appId || 'plc-simtel',
                    lastReadAt: now
                },
                $setOnInsert: { firstReadAt: now },
                $inc: { readCount: 1 }
            },
            { upsert: true, new: true }
        );

        res.json({ success: true, message: 'Progress saved.', progress });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error while saving progress.', debug: err.message });
    }
}));

// GET /api/progress/my-progress  -  all topics the logged-in user has read
app.get('/api/progress/my-progress', authMiddleware, withDB(async (req, res) => {
    try {
        const topics = await Progress.find({ user: req.user.id }).sort({ lastReadAt: -1 });
        res.json({ success: true, count: topics.length, topics });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error while fetching progress.', debug: err.message });
    }
}));

// GET /api/admin/progress/:userId  -  admin view of any user's progress
app.get('/api/admin/progress/:userId', authMiddleware, adminMiddleware, withDB(async (req, res) => {
    try {
        const topics = await Progress.find({ user: req.params.userId }).sort({ lastReadAt: -1 });
        res.json({ success: true, count: topics.length, topics });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error while fetching progress.', debug: err.message });
    }
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