// utils/otp.js
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit, e.g. "483920"
}

module.exports = { generateOTP };