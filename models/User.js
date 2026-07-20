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

  apps: { type: [String], default: ['plc-simtel'] },
  lastLogin: { type: Date }
}, { timestamps: true });

module.exports = mongoose.models.User || mongoose.model('User', userSchema);