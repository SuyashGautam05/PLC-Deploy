require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

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

// ── MongoDB (cached for serverless) ───────────────────────────
let isConnected = false;

async function connectDB() {
    if (isConnected) return;
    const rawUri = process.env.MONGODB_URI;
    const mongoUri = rawUri.includes('/?')
        ? rawUri.replace('/?', '/plc-simtel-auth?')
        : rawUri;
    await mongoose.connect(mongoUri);
    isConnected = true;
    console.log('MongoDB connected');
}

// ── User Schema ────────────────────────────────────────────────
const userSchema = new mongoose.Schema({
    name:      { type: String, required: true, trim: true },
    email:     { type: String, required: true, unique: true, lowercase: true, trim: true },
    password:  { type: String, required: true },
    role:      { type: String, enum: ['user', 'admin'], default: 'user' },
    isActive:  { type: Boolean, default: false },
    apps:      { type: [String], default: ['plc-simtel'] },
    lastLogin: { type: Date }
}, { timestamps: true });

const User = mongoose.models.User || mongoose.model('User', userSchema);

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

const withDB = (fn) => async (req, res) => {
    try {
        await connectDB();
        return fn(req, res);
    } catch (err) {
        console.error('DB connection error:', err.message);
        return res.status(500).json({ success: false, message: 'Database connection failed' });
    }
};

// ── Health check ───────────────────────────────────────────────
app.get('/', (req, res) => {
    res.json({ status: 'PLC SimTel Auth Server running', time: new Date() });
});

// ══════════════════════════════════════════════════════════════
//  AUTH ROUTES
// ══════════════════════════════════════════════════════════════

app.post('/api/auth/register', withDB(async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password)
            return res.status(400).json({ success: false, message: 'Name, email and password are required' });
        if (password.length < 6)
            return res.status(400).json({ success: false, message: 'Password must be at least 6 characters' });
        if (await User.findOne({ email }))
            return res.status(409).json({ success: false, message: 'Email already registered' });

        const hashed = await bcrypt.hash(password, 12);
        await User.create({ name, email, password: hashed });

        res.status(201).json({
            success: true,
            message: 'Registration successful. Please wait for admin approval before logging in.'
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
}));

app.post('/api/auth/login', withDB(async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password)
            return res.status(400).json({ success: false, message: 'Email and password required' });

        const user = await User.findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password)))
            return res.status(401).json({ success: false, message: 'Invalid email or password' });
        if (!user.isActive)
            return res.status(403).json({ success: false, message: 'Account not yet activated. Contact your admin.' });

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
        const user = await User.findById(req.user.id).select('-password');
        if (!user || !user.isActive)
            return res.status(403).json({ success: false, message: 'Access revoked' });
        res.json({ success: true, user: { name: user.name, email: user.email, role: user.role, apps: user.apps } });
    } catch {
        res.status(500).json({ success: false, message: 'Server error' });
    }
}));

app.post('/api/auth/logout', authMiddleware, (req, res) => {
    res.json({ success: true, message: 'Logged out' });
});

// ══════════════════════════════════════════════════════════════
//  ADMIN ROUTES
// ══════════════════════════════════════════════════════════════

app.post('/api/admin/make-admin', withDB(async (req, res) => {
    try {
        const { email, adminSecret } = req.body;
        if (adminSecret !== (process.env.ADMIN_SECRET || 'scientech-admin-2024'))
            return res.status(403).json({ success: false, message: 'Invalid admin secret' });

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
}));

app.get('/api/admin/users', authMiddleware, adminMiddleware, withDB(async (req, res) => {
    try {
        const users = await User.find({}).select('-password').sort({ createdAt: -1 });
        res.json({ success: true, users });
    } catch {
        res.status(500).json({ success: false, message: 'Server error' });
    }
}));

app.put('/api/admin/users/:id/activate', authMiddleware, adminMiddleware, withDB(async (req, res) => {
    try {
        const user = await User.findByIdAndUpdate(req.params.id, { isActive: true }, { new: true }).select('-password');
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        res.json({ success: true, message: `${user.name} activated`, user });
    } catch {
        res.status(500).json({ success: false, message: 'Server error' });
    }
}));

app.put('/api/admin/users/:id/deactivate', authMiddleware, adminMiddleware, withDB(async (req, res) => {
    try {
        const user = await User.findByIdAndUpdate(req.params.id, { isActive: false }, { new: true }).select('-password');
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        res.json({ success: true, message: `${user.name} deactivated`, user });
    } catch {
        res.status(500).json({ success: false, message: 'Server error' });
    }
}));

app.put('/api/admin/users/:id/role', authMiddleware, adminMiddleware, withDB(async (req, res) => {
    try {
        const { role } = req.body;
        if (!['user', 'admin'].includes(role))
            return res.status(400).json({ success: false, message: 'Role must be user or admin' });
        const user = await User.findByIdAndUpdate(req.params.id, { role }, { new: true }).select('-password');
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        res.json({ success: true, message: `${user.name} role set to ${role}`, user });
    } catch {
        res.status(500).json({ success: false, message: 'Server error' });
    }
}));

app.delete('/api/admin/users/:id', authMiddleware, adminMiddleware, withDB(async (req, res) => {
    try {
        const user = await User.findByIdAndDelete(req.params.id);
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        res.json({ success: true, message: `${user.name} deleted` });
    } catch {
        res.status(500).json({ success: false, message: 'Server error' });
    }
}));

app.post('/api/admin/users', authMiddleware, adminMiddleware, withDB(async (req, res) => {
    try {
        const { name, email, password, role } = req.body;
        if (!name || !email || !password)
            return res.status(400).json({ success: false, message: 'Name, email and password required' });
        if (await User.findOne({ email }))
            return res.status(409).json({ success: false, message: 'Email already registered' });

        const hashed = await bcrypt.hash(password, 12);
        const user = await User.create({ name, email, password: hashed, role: role || 'user', isActive: true });
        res.status(201).json({
            success: true,
            message: 'User created and activated',
            user: { _id: user._id, name: user.name, email: user.email, role: user.role, isActive: user.isActive }
        });
    } catch {
        res.status(500).json({ success: false, message: 'Server error' });
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