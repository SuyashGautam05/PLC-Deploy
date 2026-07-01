// ============================================================
//  create-admin.js  —  Run ONCE to create your admin account
//  Usage: node create-admin.js
//  Place this in your auth-server/ folder
// ============================================================
require('dotenv').config();

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// ── Read admin credentials from .env ─────────────────────────
const ADMIN_NAME     = process.env.ADMIN_NAME     || 'Admin';
const ADMIN_EMAIL    = process.env.ADMIN_EMAIL    || 'admin@scientech.com';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Scientech@2024';

const rawUri = process.env.MONGODB_URI;
if (!rawUri) {
    console.error('ERROR: MONGODB_URI not set in .env');
    process.exit(1);
}

const mongoUri = rawUri.includes('/?')
    ? rawUri.replace('/?', '/plc-simtel-auth?')
    : rawUri;

const userSchema = new mongoose.Schema({
    name:      { type: String, required: true, trim: true },
    email:     { type: String, required: true, unique: true, lowercase: true, trim: true },
    password:  { type: String, required: true },
    role:      { type: String, enum: ['user', 'admin'], default: 'user' },
    isActive:  { type: Boolean, default: false },
    apps:      { type: [String], default: ['plc-simtel'] },
    lastLogin: { type: Date }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

async function createAdmin() {
    console.log('Connecting to MongoDB...');
    await mongoose.connect(mongoUri);
    console.log('Connected!');

    const existing = await User.findOne({ email: ADMIN_EMAIL });

    if (existing) {
        // Update existing user to admin
        existing.role = 'admin';
        existing.isActive = true;
        existing.password = await bcrypt.hash(ADMIN_PASSWORD, 12);
        existing.name = ADMIN_NAME;
        await existing.save();
        console.log(`\n✅ Admin account updated:`);
    } else {
        // Create new admin user
        const hashed = await bcrypt.hash(ADMIN_PASSWORD, 12);
        await User.create({
            name: ADMIN_NAME,
            email: ADMIN_EMAIL,
            password: hashed,
            role: 'admin',
            isActive: true
        });
        console.log(`\n✅ Admin account created:`);
    }

    console.log(`   Email:    ${ADMIN_EMAIL}`);
    console.log(`   Password: ${ADMIN_PASSWORD}`);
    console.log(`   Role:     admin`);
    console.log(`\nYou can now login at your frontend with these credentials.\n`);

    await mongoose.disconnect();
    process.exit(0);
}

createAdmin().catch(err => {
    console.error('Failed:', err.message);
    process.exit(1);
});