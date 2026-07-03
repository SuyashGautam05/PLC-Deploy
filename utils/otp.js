// utils/otp.js
const crypto = require('crypto');

// crypto.randomInt is cryptographically secure (unlike Math.random).
function generateOTP() {
  return crypto.randomInt(100000, 1000000).toString(); // 6-digit
}

module.exports = { generateOTP };