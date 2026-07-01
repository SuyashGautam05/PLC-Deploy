// utils/validateEmail.js
// Restricts registration to real-looking @gmail.com addresses only.
// Rejects other domains and common dummy/fake patterns.

const GMAIL_REGEX = /^[a-zA-Z0-9](?:[a-zA-Z0-9.]{0,63})@gmail\.com$/;

function isValidGmail(email) {
  if (!email || typeof email !== 'string') return false;

  const trimmed = email.trim().toLowerCase();

  // Reject leading/trailing dots or consecutive dots in the local part -
  // common patterns in throwaway/dummy addresses (e.g. "..test@gmail.com")
  const localPart = trimmed.split('@')[0] || '';
  if (localPart.startsWith('.') || localPart.endsWith('.') || localPart.includes('..')) {
    return false;
  }

  // Gmail requires at least 6 characters in the local part for real accounts
  if (localPart.length < 6) return false;

  return GMAIL_REGEX.test(trimmed);
}

module.exports = { isValidGmail };