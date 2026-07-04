// utils/sendEmail.js
// Sends OTP emails using your own Gmail account over SMTP (nodemailer).
// No third-party signup - just an App Password on a Gmail account you control.
//
// Setup:
// 1. Use a Gmail account you control (a dedicated one is fine).
// 2. Turn on 2-Step Verification: Google Account -> Security.
// 3. Google Account -> Security -> App Passwords -> generate one for "Mail".
// 4. Set in env vars (both local .env AND Vercel dashboard):
//      SMTP_EMAIL=your-sending-account@gmail.com
//      SMTP_APP_PASSWORD=xxxx xxxx xxxx xxxx   (16-char app password)

const nodemailer = require('nodemailer');

let transporter = null;

function getTransporter() {
  if (transporter) return transporter;

  const { SMTP_EMAIL, SMTP_APP_PASSWORD } = process.env;
  if (!SMTP_EMAIL || !SMTP_APP_PASSWORD) {
    throw new Error('SMTP_EMAIL and SMTP_APP_PASSWORD must be set in environment variables.');
  }

  transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: SMTP_EMAIL, pass: SMTP_APP_PASSWORD }
  });

  return transporter;
}

async function sendOTPEmail(toEmail, otp, name) {
  const mailer = getTransporter();

  await mailer.sendMail({
    from: `"PLC SimTel" <${process.env.SMTP_EMAIL}>`,
    to: toEmail,
    subject: 'Your Verification Code - PLC SimTel',
    html: `
      <div style="font-family: Georgia, serif; max-width: 480px; margin: 0 auto; padding: 24px; border: 1px solid #dde2ea; border-radius: 8px;">
        <h2 style="color: #1a1a1a;">Verify your email</h2>
        <p>Hi ${name || 'there'},</p>
        <p>Use the code below to verify your email address. It expires in 5 minutes.</p>
        <p style="font-size: 32px; font-weight: 700; letter-spacing: 6px; text-align: center; background: #f4f6f9; padding: 16px; border-radius: 6px;">${otp}</p>
        <p style="font-size: 13px; color: #777;">If you didn't request this, you can safely ignore this email.</p>
      </div>
    `
  });
}

module.exports = { sendOTPEmail };