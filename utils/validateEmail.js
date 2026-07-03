// utils/validateEmail.js
// Fast format/domain check: must be shaped like a real @gmail.com address.
// Actual existence is confirmed separately via OTP verification.

const GMAIL_REGEX = /^[a-zA-Z0-9](?:[a-zA-Z0-9.]{0,63})@gmail\.com$/;

function isValidGmail(email) {
  if (!email || typeof email !== 'string') return false;

  const trimmed = email.trim().toLowerCase();

  const localPart = trimmed.split('@')[0] || '';
  if (localPart.startsWith('.') || localPart.endsWith('.') || localPart.includes('..')) {
    return false;
  }
  if (localPart.length < 6) return false;

  return GMAIL_REGEX.test(trimmed);
}

module.exports = { isValidGmail };