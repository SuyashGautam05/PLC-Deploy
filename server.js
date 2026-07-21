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

// How long a session can go without a heartbeat (from the periodic
// /api/auth/verify poll in auth-guard.js, every 90s) before it's treated as
// abandoned - e.g. the tab was closed or the browser crashed without
// hitting /logout. Set well above the poll interval so ordinary network
// hiccups or a brief page navigation don't falsely mark it stale.
const SESSION_STALE_MS = 3 * 60 * 1000;

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
    { id: user._id, email: user.email, role: user.role, name: user.name, college: user.college, collegeKey: user.collegeKey, sid },
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

// Lets either tier of admin through - college admins and the superadmin.
// Routes that must stay superadmin-only (licenses, promoting/demoting
// admins) add superAdminMiddleware on top of this.
const adminMiddleware = (req, res, next) => {
    if (req.user.role !== 'admin' && req.user.role !== 'superadmin')
        return res.status(403).json({ success: false, message: 'Admin access required' });
    next();
};

const superAdminMiddleware = (req, res, next) => {
    if (req.user.role !== 'superadmin')
        return res.status(403).json({ success: false, message: 'This action is restricted to the super admin.' });
    next();
};

// Looks up the REQUESTING admin's own college (and student quota) fresh
// from the DB, rather than trusting req.user's JWT snapshot. The JWT is
// only as current as the moment they last logged in - if their collegeKey
// or maxStudents was ever stale, missing, or changed after that login, the
// token would still carry the old value until they log in again. Resolving
// it fresh here means scoping/quota checks are always correct regardless
// of session age, and as a bonus it self-heals a legacy admin doc that has
// `college` set but never had `collegeKey` derived.
async function resolveRequesterCollege(req) {
    if (req.user.role === 'superadmin') return { college: null, collegeKey: null, maxStudents: null };
    if (req._resolvedCollege) return req._resolvedCollege; // cache per-request

    const me = await User.findById(req.user.id).select('college collegeKey maxStudents');
    const college = (me?.college || '').trim();
    const correctKey = college.toLowerCase();

    if (me && me.collegeKey !== correctKey) {
        me.collegeKey = correctKey;
        await me.save().catch(() => {}); // best-effort self-heal, don't block the request on it
    }

    req._resolvedCollege = { college, collegeKey: correctKey, maxStudents: me?.maxStudents ?? null };
    return req._resolvedCollege;
}

// A college admin may only ever touch a plain 'user' from their own
// college. Superadmin bypasses this entirely. Centralized here so every
// user-management route enforces the boundary identically.
function canManage(role, requesterCollegeKey, targetUser) {
    if (role === 'superadmin') return true;
    return targetUser.role === 'user' && targetUser.collegeKey === requesterCollegeKey;
}

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
            const withinTTL = session.expiresAt && session.expiresAt > now;
            const recentlySeen = session.lastSeenAt && (now - session.lastSeenAt) < SESSION_STALE_MS;

            if (withinTTL && recentlySeen) {
                // Genuinely still open elsewhere (a recent heartbeat proves
                // it) - refuse this login.
                return res.status(409).json({
                    success: false,
                    message: 'This account is already logged in on another device or browser. Please log out there first, or contact your admin if you think this is a mistake.'
                });
            }
            // Either the absolute TTL lapsed, or no heartbeat has arrived
            // recently (tab closed / browser crashed without a clean
            // logout) - reclaim the seat it was holding and let this
            // login proceed.
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
            lastSeenAt: now,
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
            user: { name: user.name, email: user.email, role: user.role, college: user.college, maxStudents: user.maxStudents, apps: user.apps }
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

        // Heartbeat - proves this session is still genuinely open. Without
        // this write, a closed tab would look identical to an open one
        // until the full 12h TTL ran out.
        user.activeSession.lastSeenAt = new Date();
        await user.save();

        res.json({ success: true, user: { name: user.name, email: user.email, role: user.role, college: user.college, maxStudents: user.maxStudents, apps: user.apps } });
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
//
// NOTE: There is deliberately no HTTP route to create or promote a
// superadmin. That's provisioned exclusively via `node create-admin.js`,
// run locally against the database - it needs your MongoDB credentials,
// not a request over the internet. See create-admin.js for usage.

app.get('/api/admin/users', authMiddleware, adminMiddleware, withDB(async (req, res) => {
    try {
        // College admins only ever see their own college's students - never
        // other colleges, and never other admins/the superadmin.
        const { collegeKey } = await resolveRequesterCollege(req);
        const filter = req.user.role === 'superadmin'
            ? {}
            : { collegeKey, role: 'user' };
        const users = await User.find(filter).select('-password -otp -activeSession.token').sort({ createdAt: -1 });
        res.json({ success: true, users });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
}));

// Admin creates the account directly. Unlike self-registration, this does
// NOT go through OTP email verification - the admin already vetted this
// person by typing in their details themselves, so the account is created
// already active and the student can log in immediately with the password
// the admin set. (Sending an OTP here was pointless anyway: the student
// never visits the register/verify-otp pages, so they had no way to act
// on the code that got emailed to them - that was the login deadlock.)
//
// Scoping: a college admin can only ever create a plain 'user' account, and
// it's silently pinned to their own college regardless of what's submitted -
// this is what stops one college admin from planting an account in another
// college's group. Only the superadmin can create another admin.
app.post('/api/admin/users', authMiddleware, adminMiddleware, withDB(async (req, res) => {
    let createdUser = null;
    try {
        const isSuperAdmin = req.user.role === 'superadmin';
        const { name, email, password } = req.body;
        let { role, college, maxStudents } = req.body;

        if (!name || !email || !password)
            return res.status(400).json({ success: false, message: 'Name, email and password required' });
        if (password.length < 6)
            return res.status(400).json({ success: false, message: 'Password must be at least 6 characters.' });

        if (!isSuperAdmin) {
            role = 'user';
            const { college: myCollege, collegeKey: myCollegeKey, maxStudents: myQuota } = await resolveRequesterCollege(req);
            college = myCollege; // force to the college admin's own college, resolved fresh (not from the JWT snapshot)

            // Enforce this admin's student-creation quota (set by the
            // superadmin). null quota = unlimited (legacy admins from
            // before this field existed).
            if (myQuota !== null) {
                const currentCount = await User.countDocuments({ collegeKey: myCollegeKey, role: 'user' });
                if (currentCount >= myQuota) {
                    return res.status(403).json({
                        success: false,
                        message: `You've reached your student limit (${currentCount}/${myQuota}). Ask the super admin to raise it if you need to add more.`
                    });
                }
            }
        } else {
            role = role === 'admin' ? 'admin' : 'user'; // superadmin can create students or college admins, never another superadmin here
            if (role === 'admin') {
                const quota = Number(maxStudents);
                if (!Number.isInteger(quota) || quota < 1) {
                    return res.status(400).json({ success: false, message: 'A student limit (whole number, at least 1) is required when creating a college admin.' });
                }
                maxStudents = quota;
            } else {
                maxStudents = null;
            }
        }

        // College is required for every account created here, not just
        // admins - a student with no college can't be matched to a
        // license seat or show up in the grouped college view.
        if (!college || college.trim().length < 2) {
            return res.status(400).json({ success: false, message: 'A college name is required.' });
        }

        const normalizedEmail = email.trim().toLowerCase();

        if (!isValidGmail(normalizedEmail)) {
            return res.status(400).json({ success: false, message: 'Only real @gmail.com addresses are allowed.' });
        }
        if (await User.findOne({ email: normalizedEmail })) {
            return res.status(409).json({ success: false, message: 'Email already registered' });
        }

        const hashed = await bcrypt.hash(password, 12);
        createdUser = await User.create({
            name, email: normalizedEmail, password: hashed, role,
            college: college.trim(),
            maxStudents: role === 'admin' ? maxStudents : null,
            isActive: true, emailVerified: true, registrationSource: 'admin'
        });

        res.status(201).json({
            success: true,
            message: `Account created and active. Share these credentials with ${createdUser.name} - they can log in right away.`,
            user: { _id: createdUser._id, name: createdUser.name, email: createdUser.email, role: createdUser.role, college: createdUser.college, maxStudents: createdUser.maxStudents, isActive: createdUser.isActive }
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
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        const { collegeKey: _ck } = await resolveRequesterCollege(req);
        if (!canManage(req.user.role, _ck, user)) return res.status(403).json({ success: false, message: 'You can only manage students from your own college.' });
        user.isActive = true;
        await user.save();
        const safeUser = await User.findById(user._id).select('-password -otp -activeSession.token');
        res.json({ success: true, message: `${user.name} activated`, user: safeUser });
    } catch (err) { console.error(err); res.status(500).json({ success: false, message: 'Server error' }); }
}));

app.put('/api/admin/users/:id/deactivate', authMiddleware, adminMiddleware, withDB(async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        const { collegeKey: _ck } = await resolveRequesterCollege(req);
        if (!canManage(req.user.role, _ck, user)) return res.status(403).json({ success: false, message: 'You can only manage students from your own college.' });
        user.isActive = false;
        if (user.activeSession && user.activeSession.token) await releaseSeat(user);
        await user.save();
        const safeUser = await User.findById(user._id).select('-password -otp -activeSession.token');
        res.json({ success: true, message: `${user.name} deactivated`, user: safeUser });
    } catch (err) { console.error(err); res.status(500).json({ success: false, message: 'Server error' }); }
}));

// Lets the superadmin fix/assign a user's college (e.g. legacy accounts
// created before this field existed, or typo corrections) so grouping in
// the admin panel - and license-seat matching - stay accurate. Kept
// superadmin-only: a college admin reassigning a student's college could
// otherwise be used to move students in or out of their own scope.
app.put('/api/admin/users/:id/college', authMiddleware, adminMiddleware, superAdminMiddleware, withDB(async (req, res) => {
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
        const { collegeKey: _ck } = await resolveRequesterCollege(req);
        if (!canManage(req.user.role, _ck, user)) return res.status(403).json({ success: false, message: 'You can only manage students from your own college.' });
        if (!user.activeSession || !user.activeSession.token) {
            return res.status(400).json({ success: false, message: `${user.name} is not currently logged in.` });
        }
        await releaseSeat(user);
        await user.save();
        res.json({ success: true, message: `${user.name} has been logged out and their seat freed.` });
    } catch (err) { console.error(err); res.status(500).json({ success: false, message: 'Server error' }); }
}));

// Promoting/demoting between student and college-admin is a superadmin-only
// action - a college admin must never be able to create or remove admins,
// including themselves or peers.
app.put('/api/admin/users/:id/role', authMiddleware, adminMiddleware, superAdminMiddleware, withDB(async (req, res) => {
    try {
        const { role, college, maxStudents } = req.body;
        if (!['user', 'admin'].includes(role))
            return res.status(400).json({ success: false, message: 'Role must be user or admin' });

        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });

        if (role === 'admin') {
            const targetCollege = (college || user.college || '').trim();
            if (targetCollege.length < 2) {
                return res.status(400).json({ success: false, message: 'A college is required to make someone a college admin.' });
            }
            const quota = Number(maxStudents);
            if (!Number.isInteger(quota) || quota < 1) {
                return res.status(400).json({ success: false, message: 'A student limit (whole number, at least 1) is required to make someone a college admin.' });
            }
            user.college = targetCollege; // pre-save hook re-derives collegeKey
            user.maxStudents = quota;
        } else {
            user.maxStudents = null; // no longer an admin - quota is meaningless
        }
        user.role = role;
        await user.save();

        const safeUser = await User.findById(user._id).select('-password -otp -activeSession.token');
        res.json({ success: true, message: `${user.name} role set to ${role}`, user: safeUser });
    } catch (err) { console.error(err); res.status(500).json({ success: false, message: 'Server error' }); }
}));

// Lets the superadmin change an existing college admin's student-creation
// quota later, without having to demote/repromote them.
app.put('/api/admin/users/:id/max-students', authMiddleware, adminMiddleware, superAdminMiddleware, withDB(async (req, res) => {
    try {
        const quota = Number(req.body.maxStudents);
        if (!Number.isInteger(quota) || quota < 0) {
            return res.status(400).json({ success: false, message: 'maxStudents must be a whole number (0 or more).' });
        }
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        if (user.role !== 'admin') {
            return res.status(400).json({ success: false, message: 'Only college admins have a student limit.' });
        }
        user.maxStudents = quota;
        await user.save();
        const safeUser = await User.findById(user._id).select('-password -otp -activeSession.token');
        res.json({ success: true, message: `${user.name}'s student limit set to ${quota}`, user: safeUser });
    } catch (err) { console.error(err); res.status(500).json({ success: false, message: 'Server error' }); }
}));

app.delete('/api/admin/users/:id', authMiddleware, adminMiddleware, withDB(async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        const { collegeKey: _ck } = await resolveRequesterCollege(req);
        if (!canManage(req.user.role, _ck, user)) return res.status(403).json({ success: false, message: 'You can only manage students from your own college.' });
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
app.get('/api/admin/colleges', authMiddleware, adminMiddleware, superAdminMiddleware, withDB(async (req, res) => {
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
app.post('/api/admin/colleges', authMiddleware, adminMiddleware, superAdminMiddleware, withDB(async (req, res) => {
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
app.put('/api/admin/colleges/:id', authMiddleware, adminMiddleware, superAdminMiddleware, withDB(async (req, res) => {
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
app.delete('/api/admin/colleges/:id', authMiddleware, adminMiddleware, superAdminMiddleware, withDB(async (req, res) => {
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

// GET /api/admin/progress/:userId  -  admin view of a user's progress
// (college admins may only view students from their own college)
app.get('/api/admin/progress/:userId', authMiddleware, adminMiddleware, withDB(async (req, res) => {
    try {
        const targetUser = await User.findById(req.params.userId);
        if (!targetUser) return res.status(404).json({ success: false, message: 'User not found' });
        const { collegeKey: _ck } = await resolveRequesterCollege(req);
        if (!canManage(req.user.role, _ck, targetUser)) return res.status(403).json({ success: false, message: 'You can only view students from your own college.' });

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