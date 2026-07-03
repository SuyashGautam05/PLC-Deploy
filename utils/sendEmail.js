// utils/sendEmail.js
// Sends OTP emails using the Resend API (https://resend.com).
// No SMTP, no Gmail App Passwords, nothing to rotate by hand - just one API key.
//
// ── One-time setup (no code changes after this) ──────────────────────
// 1. Sign up free at https://resend.com (no credit card required).
//    Free tier: 3,000 emails/month, 100/day - plenty for OTP verification.
// 2. In the Resend dashboard: Home -> API Keys -> Create API Key. Copy it.
// 3. On Vercel: Project -> Settings -> Environment Variables, add:
//      RESEND_API_KEY = re_xxxxxxxxxxxxxxxx
//      FROM_EMAIL     = PLC SimTel <onboarding@resend.dev>
//    "onboarding@resend.dev" is Resend's shared test sender - it works
//    immediately with zero setup, but lands in inboxes as coming from
//    Resend. Whenever you want emails to appear from your own domain,
//    verify that domain in Resend (Domains tab, add a couple of DNS
//    records), then just change FROM_EMAIL to e.g.
//    "PLC SimTel <noreply@yourdomain.com>" - purely an env var change,
//    no redeploy of code needed.
// 4. Redeploy once so this file is live. From then on, rotating or
//    changing the sender only ever means updating env vars on Vercel.

async function sendOTPEmail(toEmail, otp, name) {
  const { RESEND_API_KEY, FROM_EMAIL } = process.env;
  if (!RESEND_API_KEY) {
    throw new Error('RESEND_API_KEY must be set in environment variables.');
  }

  const from = FROM_EMAIL || 'PLC SimTel <onboarding@resend.dev>';

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${RESEND_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      from,
      to: toEmail,
      subject: 'Your Verification Code - PLC SimTel',
      html: `
        <div style="font-family: Georgia, serif; max-width: 480px; margin: 0 auto; padding: 24px; border: 1px solid #dde2ea; border-radius: 8px;">
          <h2 style="color: #1a1a1a;">Verify your email</h2>
          <p>Hi ${name || 'there'},</p>
          <p>Use the code below to verify your email and activate your account on the PLC SimTel training portal:</p>
          <p style="font-size: 32px; font-weight: 700; letter-spacing: 6px; text-align: center; background: #f4f6f9; padding: 16px; border-radius: 6px;">${otp}</p>
          <p>This code expires in 5 minutes. If you didn't expect this, you can ignore this email.</p>
        </div>
      `
    })
  });

  if (!res.ok) {
    const errBody = await res.json().catch(() => ({}));
    throw new Error(`Resend API error: ${errBody.message || res.statusText}`);
  }
}

module.exports = { sendOTPEmail };