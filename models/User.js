const mongoose = require('mongoose');

// Basic format check only - this stays permissive at the schema level.
// The stricter "must be a real @gmail.com address" rule is enforced
// separately in server.js via isValidGmail(), only at account-creation time.
// Keeping a strict validator HERE would break every .save() on any existing
// non-Gmail account (e.g. an admin account), since Mongoose re-validates the
// whole document - including unchanged fields - on every save.
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    validate: {
      validator: (v) => EMAIL_REGEX.test(v),
      message: (props) => `${props.value} is not a valid email address.`
    }
  },
  password: { type: String, required: true },
  role: { type: String, enum: ['admin', 'user'], default: 'user' },

  // College / institute the user belongs to. Free text (not enum) since we
  // don't control the list of colleges — admin panel groups users by this
  // value. 'Unspecified' is used as the grouping bucket for legacy accounts
  // created before this field existed.
  college: { type: String, trim: true, default: '' },

  // Lowercase-trimmed mirror of `college`, auto-derived below. This is what
  // license-seat lookups match against (College.nameKey), so a user typing
  // "IET DAVV" vs "iet davv" still hits the same seat pool.
  collegeKey: { type: String, trim: true, lowercase: true, default: '', index: true },

  // isActive = admin has approved login access.
  isActive: { type: Boolean, default: false },

  // emailVerified = user proved they own this inbox via OTP.
  // Kept separate from isActive: verifying email is NOT the same as being
  // approved to log in. Self-registered users still need admin approval
  // after verifying; admin-created users are auto-approved on OTP verify
  // since an admin already vetted them by creating the account.
  emailVerified: { type: Boolean, default: false },

  // 'self'  = user registered themselves via the public Register form -> needs admin approval after OTP verify.
  // 'admin' = an admin created this account -> auto-approved on OTP verify.
  registrationSource: { type: String, enum: ['self', 'admin'], default: 'self' },

  otp: { type: String, default: null },
  otpExpires: { type: Date, default: null },
  otpAttempts: { type: Number, default: 0 },
  otpLastSentAt: { type: Date, default: null },

  // Tracks the ONE currently-valid login session for this account. `token`
  // is a random session id (not the JWT itself) embedded in the JWT's `sid`
  // claim - a request is only honored if its JWT's sid matches this value.
  // A second login attempt while this is still unexpired is rejected, which
  // is what enforces "one active login per account at a time". Set to null
  // whenever the session ends (logout, expiry, or admin force-logout) so the
  // seat/slot is freed.
  activeSession: {
    token: { type: String, default: null },
    loginAt: { type: Date, default: null },
    expiresAt: { type: Date, default: null },
    userAgent: { type: String, default: '' }
  },

  apps: { type: [String], default: ['plc-simtel'] },
  lastLogin: { type: Date }
}, { timestamps: true });

// Keep collegeKey in sync whenever college changes, so license lookups and
// admin grouping never drift out of step with the display value.
userSchema.pre('save', function (next) {
  if (this.isModified('college')) {
    this.collegeKey = (this.college || '').trim().toLowerCase();
  }
  next();
});

module.exports = mongoose.models.User || mongoose.model('User', userSchema);