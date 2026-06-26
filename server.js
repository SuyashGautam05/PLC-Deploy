// ============================================================
//  PLC SimTel - Central Auth Server
//  Deploy this on Render.com (free tier works)
//  Set environment variables in Render dashboard:
//    MONGODB_URI   - your MongoDB Atlas connection string
//    JWT_SECRET    - any long random string (keep secret)
//    ADMIN_SECRET  - one-time secret to promote a user to admin
//    CLIENT_ORIGIN - your frontend URL e.g. https://plc-simtel.onrender.com
// ============================================================

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Middleware ───────────────────────────────────────────────
app.use(express.json());
app.use(cors({
    origin: process.env.CLIENT_ORIGIN || '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// ── MongoDB Connection ───────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/plc-simtel-auth')
    .then(() => console.log('✅ MongoDB connected'))
    .catch(err => { console.error('❌ MongoDB error:', err); process.exit(1); });

// ── User Schema ──────────────────────────────────────────────
const userSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    isActive: { type: Boolean, default: false },  // Admin must activate
    apps: { type: [String], default: ['plc-simtel'] }, // which apps user can access
    createdAt: { type: Date, default: Date.now },
    lastLogin: { type: Date }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// ── Helpers ──────────────────────────────────────────────────
const signToken = (user) => jwt.sign(
    { id: user._id, email: user.email, role: user.role, name: user.name },
    process.env.JWT_SECRET || 'change-this-secret-in-production',
    { expiresIn: '7d' }
);

const authMiddleware = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ success: false, message: 'No token provided' });
    }
    try {
        const token = authHeader.split(' ')[1];
        req.user = jwt.verify(token, process.env.JWT_SECRET || 'change-this-secret-in-production');
        next();
    } catch {
        return res.status(401).json({ success: false, message: 'Invalid or expired token' });
    }
};

const adminMiddleware = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ success: false, message: 'Admin access required' });
    }
    next();
};

// ── Health Check ─────────────────────────────────────────────
app.get('/', (req, res) => {
    res.json({ status: 'PLC SimTel Auth Server running', time: new Date() });
});

// ══════════════════════════════════════════════════════════════
//  AUTH ROUTES
// ══════════════════════════════════════════════════════════════

// POST /api/auth/register
// Anyone can register, but account is inactive until admin approves
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) {
            return res.status(400).json({ success: false, message: 'Name, email and password are required' });
        }
        if (password.length < 6) {
            return res.status(400).json({ success: false, message: 'Password must be at least 6 characters' });
        }

        const existing = await User.findOne({ email });
        if (existing) {
            return res.status(409).json({ success: false, message: 'Email already registered' });
        }

        const hashed = await bcrypt.hash(password, 12);
        const user = await User.create({ name, email, password: hashed });

        res.status(201).json({
            success: true,
            message: 'Registration successful. Please wait for admin approval before logging in.'
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'Email and password required' });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ success: false, message: 'Invalid email or password' });
        }

        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(401).json({ success: false, message: 'Invalid email or password' });
        }

        if (!user.isActive) {
            return res.status(403).json({ success: false, message: 'Account not yet activated. Contact your admin.' });
        }

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
});

// GET /api/auth/verify  — client calls this on every page load
app.get('/api/auth/verify', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        if (!user || !user.isActive) {
            return res.status(403).json({ success: false, message: 'Access revoked' });
        }
        res.json({ success: true, user: { name: user.name, email: user.email, role: user.role, apps: user.apps } });
    } catch {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// POST /api/auth/logout  — optional server-side log
app.post('/api/auth/logout', authMiddleware, (req, res) => {
    res.json({ success: true, message: 'Logged out' });
});

// ══════════════════════════════════════════════════════════════
//  ADMIN ROUTES  (all require admin role)
// ══════════════════════════════════════════════════════════════

// POST /api/admin/make-admin
// Use ADMIN_SECRET env var to promote first admin
// Body: { email, adminSecret }
app.post('/api/admin/make-admin', async (req, res) => {
    try {
        const { email, adminSecret } = req.body;
        if (adminSecret !== (process.env.ADMIN_SECRET || 'scientech-admin-2024')) {
            return res.status(403).json({ success: false, message: 'Invalid admin secret' });
        }
        const user = await User.findOneAndUpdate(
            { email },
            { role: 'admin', isActive: true },
            { new: true }
        );
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        res.json({ success: true, message: `${email} is now an admin` });
    } catch {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// GET /api/admin/users  — list all users
app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const users = await User.find({}).select('-password').sort({ createdAt: -1 });
        res.json({ success: true, users });
    } catch {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// PUT /api/admin/users/:id/activate  — grant access
app.put('/api/admin/users/:id/activate', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const user = await User.findByIdAndUpdate(
            req.params.id,
            { isActive: true },
            { new: true }
        ).select('-password');
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        res.json({ success: true, message: `${user.name} activated`, user });
    } catch {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// PUT /api/admin/users/:id/deactivate  — revoke access
app.put('/api/admin/users/:id/deactivate', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const user = await User.findByIdAndUpdate(
            req.params.id,
            { isActive: false },
            { new: true }
        ).select('-password');
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        res.json({ success: true, message: `${user.name} deactivated`, user });
    } catch {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// PUT /api/admin/users/:id/role  — change role (user/admin)
app.put('/api/admin/users/:id/role', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { role } = req.body;
        if (!['user', 'admin'].includes(role)) {
            return res.status(400).json({ success: false, message: 'Role must be user or admin' });
        }
        const user = await User.findByIdAndUpdate(
            req.params.id,
            { role },
            { new: true }
        ).select('-password');
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        res.json({ success: true, message: `${user.name} role set to ${role}`, user });
    } catch {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// DELETE /api/admin/users/:id  — delete user
app.delete('/api/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const user = await User.findByIdAndDelete(req.params.id);
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        res.json({ success: true, message: `${user.name} deleted` });
    } catch {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// POST /api/admin/users  — admin creates user directly (already active)
app.post('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { name, email, password, role } = req.body;
        if (!name || !email || !password) {
            return res.status(400).json({ success: false, message: 'Name, email and password required' });
        }
        const existing = await User.findOne({ email });
        if (existing) {
            return res.status(409).json({ success: false, message: 'Email already registered' });
        }
        const hashed = await bcrypt.hash(password, 12);
        const user = await User.create({
            name, email, password: hashed,
            role: role || 'user',
            isActive: true  // Admin-created users are active immediately
        });
        res.status(201).json({
            success: true,
            message: 'User created and activated',
            user: { _id: user._id, name: user.name, email: user.email, role: user.role, isActive: user.isActive }
        });
    } catch {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// ── Start ────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`🚀 Auth server running on port ${PORT}`));