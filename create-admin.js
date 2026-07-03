// ============================================================
//  create-admin.js  —  Run ONCE to create your admin account
//  Usage: node create-admin.js
// ============================================================
require('dotenv').config();

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const User = require('./models/User');

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

async function createAdmin() {
    console.log('Connecting to MongoDB...');
    await mongoose.connect(mongoUri);
    console.log('Connected!');

    const email = ADMIN_EMAIL.trim().toLowerCase();
    const existing = await User.findOne({ email });

    if (existing) {
        existing.role = 'admin';
        existing.isActive = true;
        existing.password = await bcrypt.hash(ADMIN_PASSWORD, 12);
        existing.name = ADMIN_NAME;
        await existing.save();
        console.log('\nAdmin account updated:');
    } else {
        const hashed = await bcrypt.hash(ADMIN_PASSWORD, 12);
        await User.create({
            name: ADMIN_NAME,
            email,
            password: hashed,
            role: 'admin',
            isActive: true
        });
        console.log('\nAdmin account created:');
    }

    console.log(`   Email:    ${email}`);
    console.log(`   Password: ${ADMIN_PASSWORD}`);
    console.log(`   Role:     admin`);
    console.log('\nYou can now login at your frontend with these credentials.\n');

    await mongoose.disconnect();
    process.exit(0);
}

createAdmin().catch(err => {
    console.error('Failed:', err.message);
    process.exit(1);
});