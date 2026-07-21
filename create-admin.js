// ============================================================
//  create-admin.js  —  Run ONCE, locally, to create the SUPER ADMIN
//  (the software owner's account - full access to every college).
//
//  This is deliberately a script you run from your own machine with
//  `node create-admin.js`, NOT an HTTP route. There is no API endpoint
//  anywhere in server.js that can create or promote a superadmin - the
//  only way in is having your MongoDB credentials, which only you have.
//
//  Usage:
//    1. Fill in ADMIN_NAME / ADMIN_EMAIL / ADMIN_PASSWORD, either
//       directly below or via a local .env (recommended so you never
//       commit real credentials):
//         ADMIN_NAME=Your Name
//         ADMIN_EMAIL=you@example.com
//         ADMIN_PASSWORD=a-strong-password
//    2. Make sure MONGODB_URI in your .env points at the SAME database
//       your deployed server.js uses (copy it from Vercel's env vars).
//    3. Run:  node create-admin.js
//    4. Log in at /login.html with those credentials - you'll land as
//       superadmin in /admin.html.
// ============================================================
require('dotenv').config();

const dns = require('dns');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const readline = require('readline');
const User = require('./models/User');

// Many Windows setups (and some routers/VPNs/ISPs) can't resolve the
// mongodb+srv:// SRV record through the default system DNS resolver, which
// shows up as "querySrv ETIMEOUT _mongodb._tcp.<cluster>.mongodb.net".
// Forcing Node to ask Google/Cloudflare DNS directly instead of the OS
// resolver fixes this in the vast majority of cases.
dns.setServers(['8.8.8.8', '1.1.1.1']);

const ADMIN_NAME     = process.env.ADMIN_NAME     || 'Admin';
const ADMIN_EMAIL    = process.env.ADMIN_EMAIL    || '';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';

const rawUri = process.env.MONGODB_URI;
if (!rawUri) {
    console.error('ERROR: MONGODB_URI not set in .env');
    process.exit(1);
}
if (!ADMIN_EMAIL || !ADMIN_PASSWORD) {
    console.error('ERROR: set ADMIN_EMAIL and ADMIN_PASSWORD in your .env before running this script.');
    process.exit(1);
}
if (ADMIN_PASSWORD.length < 6) {
    console.error('ERROR: ADMIN_PASSWORD must be at least 6 characters.');
    process.exit(1);
}

const mongoUri = rawUri.includes('/?')
    ? rawUri.replace('/?', '/plc-simtel-auth?')
    : rawUri;

function ask(question) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    return new Promise(resolve => rl.question(question, ans => { rl.close(); resolve(ans.trim().toLowerCase()); }));
}

async function createSuperAdmin() {
    console.log('Connecting to MongoDB...');
    await mongoose.connect(mongoUri);
    console.log('Connected!');

    const email = ADMIN_EMAIL.trim().toLowerCase();

    // Safety check: if a DIFFERENT superadmin already exists, make sure this
    // is intentional before creating a second one. (Having exactly one
    // superadmin is the normal setup - nothing stops you from having more,
    // but it's easy to do by accident by re-running this with a new email.)
    const existingSuperAdmins = await User.find({ role: 'superadmin', email: { $ne: email } }).select('name email');
    if (existingSuperAdmins.length > 0) {
        console.log('\nA superadmin already exists on this database:');
        existingSuperAdmins.forEach(u => console.log(`   - ${u.name} <${u.email}>`));
        const answer = await ask('\nCreate/update ANOTHER superadmin account too? (yes/no): ');
        if (answer !== 'yes' && answer !== 'y') {
            console.log('Cancelled. No changes made.');
            await mongoose.disconnect();
            process.exit(0);
        }
    }

    const existing = await User.findOne({ email });
    const hashed = await bcrypt.hash(ADMIN_PASSWORD, 12);

    if (existing) {
        existing.role = 'superadmin';
        existing.isActive = true;
        existing.emailVerified = true;
        existing.password = hashed;
        existing.name = ADMIN_NAME;
        await existing.save();
        console.log('\nSuper admin account updated:');
    } else {
        await User.create({
            name: ADMIN_NAME,
            email,
            password: hashed,
            role: 'superadmin',
            isActive: true,
            emailVerified: true,
            registrationSource: 'admin'
        });
        console.log('\nSuper admin account created:');
    }

    console.log(`   Name:     ${ADMIN_NAME}`);
    console.log(`   Email:    ${email}`);
    console.log(`   Role:     superadmin (full access - every college, all licenses)`);
    console.log('\nLog in at your frontend with this email + password.');
    console.log('For security, clear ADMIN_PASSWORD from your .env once this is done.\n');

    await mongoose.disconnect();
    process.exit(0);
}

createSuperAdmin().catch(err => {
    console.error('\nFailed:', err.message);

    if (err.message && err.message.includes('querySrv')) {
        console.error(`
This is a DNS problem talking to MongoDB Atlas, not a bug in the script.
It already tried forcing Google/Cloudflare DNS (8.8.8.8 / 1.1.1.1) - if
you're still seeing this, your network is likely blocking DNS SRV lookups
outright (common on some office networks, VPNs, or mobile hotspots).

Try one of these:
  1. Switch networks (e.g. a phone hotspot) and run the script again -
     if it works there, it confirms your usual network is blocking it.
  2. Use the NON-SRV connection string instead, which skips the SRV DNS
     lookup entirely:
       - Atlas dashboard -> Database -> Connect -> Drivers
       - Below the mongodb+srv:// string there's usually a link/toggle
         for the older "standard connection string" format
         (mongodb://host1,host2,host3/...) - use that as MONGODB_URI
         in your .env instead.
  3. If you're on a VPN, briefly disconnect it and retry.
`);
    }

    process.exit(1);
});