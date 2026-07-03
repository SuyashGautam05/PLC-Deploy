// utils/sendEmail.js
// Sends OTP emails using SendGrid's Mail Send API (https://sendgrid.com).
// Uses "Single Sender Verification" - you verify ONE email address you own
// (no domain purchase, no DNS records) and can then send to ANY recipient.
//
// ── One-time setup (no code changes after this) ──────────────────────
// 1. Sign up free at https://sendgrid.com (Twilio SendGrid).
//    Free tier: 100 emails/day forever - plenty for OTP verification.
// 2. Settings -> Sender Authentication -> "Verify a Single Sender".
//    Enter an email address you control (e.g. your own Gmail address).
//    SendGrid emails a confirmation link to that address - click it.
//    This is the ONLY address you're allowed to send FROM, but you can
//    send TO anyone once it's verified.
// 3. Settings -> API Keys -> Create API Key (Restricted Access is fine,
//    just enable "Mail Send" permission). Copy the key - shown once.
// 4. On Vercel: Project -> Settings -> Environment Variables, set for
//    BOTH Production and Preview:
//      SENDGRID_API_KEY = SG.xxxxxxxxxxxxxxxx
//      FROM_EMAIL        = the exact email you verified in step 2
//    (FROM_EMAIL must match the verified sender exactly, or SendGrid
//    will reject the send.)
// 5. Redeploy once so this file is live.

async function sendOTPEmail(toEmail, otp, name) {
  const { SENDGRID_API_KEY, FROM_EMAIL } = process.env;
  if (!SENDGRID_API_KEY) {
    throw new Error('SENDGRID_API_KEY must be set in environment variables.');
  }
  if (!FROM_EMAIL) {
    throw new Error('FROM_EMAIL must be set to your SendGrid-verified single sender address.');
  }

  const res = await fetch('https://api.sendgrid.com/v3/mail/send', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${SENDGRID_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      personalizations: [{ to: [{ email: toEmail }] }],
      from: { email: FROM_EMAIL, name: 'PLC SimTel' },
      subject: 'Your Verification Code - PLC SimTel',
      content: [{
        type: 'text/html',
        value: `
          <div style="font-family: Georgia, serif; max-width: 480px; margin: 0 auto; padding: 24px; border: 1px solid #dde2ea; border-radius: 8px;">
            <h2 style="color: #1a1a1a;">Verify your email</h2>
            <p>Hi ${name || 'there'},</p>
            <p>Use the code below to verify your email and activate your account on the PLC SimTel training portal:</p>
            <p style="font-size: 32px; font-weight: 700; letter-spacing: 6px; text-align: center; background: #f4f6f9; padding: 16px; border-radius: 6px;">${otp}</p>
            <p>This code expires in 5 minutes. If you didn't expect this, you can ignore this email.</p>
          </div>
        `
      }]
    })
  });

  if (!res.ok) {
    const errBody = await res.text().catch(() => '');
    throw new Error(`SendGrid API error (${res.status}): ${errBody}`);
  }
}

module.exports = { sendOTPEmail };