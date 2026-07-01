// routes/verify.js
// PUBLIC routes (no admin token needed) - called by the user themselves
// from verify-otp.html to activate their own account.

const express = require('express');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const { generateOTP } = require('../utils/otp');
const { sendOTPEmail } = require('../utils/sendEmail');

const router = express.Router();

// POST /api/auth/verify-otp   body: { email, otp }
router.post('/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) {
      return res.status(400).json({ success: false, message: 'Email and OTP are required.' });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      return res.status(404).json({ success: false, message: 'No account found with this email.' });
    }
    if (user.isActive) {
      return res.status(400).json({ success: false, message: 'This account is already verified. You can log in.' });
    }
    if (!user.otp || !user.otpExpires || user.otpExpires < new Date()) {
      return res.status(400).json({ success: false, message: 'This code has expired. Please request a new one.' });
    }

    const match = await bcrypt.compare(otp, user.otp);
    if (!match) {
      return res.status(400).json({ success: false, message: 'Incorrect code. Please try again.' });
    }

    user.isActive = true;
    user.otp = null;
    user.otpExpires = null;
    await user.save();

    res.json({ success: true, message: 'Email verified! You can now log in.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error while verifying code.' });
  }
});

// POST /api/auth/resend-otp   body: { email }
router.post('/resend-otp', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ success: false, message: 'Email is required.' });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      return res.status(404).json({ success: false, message: 'No account found with this email.' });
    }
    if (user.isActive) {
      return res.status(400).json({ success: false, message: 'This account is already verified. You can log in.' });
    }

    const rawOtp = generateOTP();
    user.otp = await bcrypt.hash(rawOtp, 10);
    user.otpExpires = new Date(Date.now() + 10 * 60 * 1000);
    await user.save();

    await sendOTPEmail(normalizedEmail, rawOtp, user.name);

    res.json({ success: true, message: 'A new code has been sent to your email.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Could not resend code. Please try again.' });
  }
});

module.exports = router;