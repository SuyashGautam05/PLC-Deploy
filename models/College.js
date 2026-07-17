const mongoose = require('mongoose');

// One document per licensed college/company. `activeCount` is a live
// counter of how many of that college's users currently hold an unexpired
// login session - it's incremented atomically at login (see the
// findOneAndUpdate + $expr guard in /api/auth/login) and decremented via
// releaseSeat() on logout/expiry/force-logout, so it never needs a separate
// reconciliation pass except when an admin lowers licenseLimit below the
// current activeCount (handled by reconcileCollegeSeats in server.js).
const collegeSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },

  // Lowercase-trimmed lookup key, matched against User.collegeKey. Kept as
  // a separate indexed field (rather than a virtual) so Mongo can enforce
  // uniqueness and so queries like { nameKey } stay simple index lookups.
  nameKey: { type: String, required: true, unique: true, trim: true, lowercase: true, index: true },

  // Number of seats purchased - the max simultaneous logged-in users allowed
  // for this college at once.
  licenseLimit: { type: Number, required: true, min: 1 },

  // Live count of users from this college currently holding an unexpired
  // session. Should never exceed licenseLimit in normal operation - the
  // login route only reserves a seat via an atomic $expr guard, and
  // reconcileCollegeSeats() corrects any drift after an admin edit.
  activeCount: { type: Number, default: 0, min: 0 },

  contactEmail: { type: String, trim: true, default: '' },
  notes: { type: String, trim: true, default: '' }
}, { timestamps: true });

module.exports = mongoose.models.College || mongoose.model('College', collegeSchema);