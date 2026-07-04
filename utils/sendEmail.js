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

  const smtpEmail = (process.env.SMTP_EMAIL || '').trim();
  const smtpPass  = (process.env.SMTP_APP_PASSWORD || '').trim();

  // LOG credentials status (never log the actual password)
  console.log('[sendEmail] SMTP_EMAIL:', smtpEmail || '(NOT SET)');
  console.log('[sendEmail] SMTP_APP_PASSWORD:', smtpPass ? '[SET, ' + smtpPass.length + ' chars]' : '(NOT SET)');

  if (!smtpEmail || !smtpPass) {
    const missing = [];
    if (!smtpEmail) missing.push('SMTP_EMAIL');
    if (!smtpPass) missing.push('SMTP_APP_PASSWORD');
    const err = new Error(
      `Missing env vars: ${missing.join(', ')}. ` +
      `Set them in your .env locally AND in Vercel dashboard -> Settings -> Environment Variables.`
    );
    err.code = 'MISSING_CREDENTIALS';
    throw err;
  }

  transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: smtpEmail, pass: smtpPass }
  });

  return transporter;
}

async function sendOTPEmail(toEmail, otp, name) {
  const mailer = getTransporter();

  try {
    const info = await mailer.sendMail({
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
    console.log(`[sendEmail] OTP sent to ${toEmail}, messageId: ${info.messageId}`);
  } catch (err) {
    // Log FULL error details so Vercel logs show exactly what failed
    console.error('[sendEmail] FAILED to send email to', toEmail);
    console.error('[sendEmail] Error:', err.message);
    if (err.code) console.error('[sendEmail] SMTP code:', err.code);
    if (err.response) console.error('[sendEmail] SMTP response:', err.response);
    if (err.command) console.error('[sendEmail] SMTP command:', err.command);

    // Re-throw with a clearer message for the API response
    const friendlyMsg = err.code === 'EAUTH'
      ? 'SMTP authentication failed. Check your SMTP_EMAIL and SMTP_APP_PASSWORD.'
      : err.code === 'ETIMEDOUT'
      ? 'SMTP connection timed out. Vercel serverless may block outbound port 587/465.'
      : err.code === 'ECONNECTION'
      ? 'Could not connect to Gmail SMTP. Vercel may restrict outbound connections.'
      : `Email send failed: ${err.message}`;

    const enhanced = new Error(friendlyMsg);
    enhanced.code = err.code;
    enhanced.originalMessage = err.message;
    throw enhanced;
  }
}

module.exports = { sendOTPEmail };