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

  isActive: { type: Boolean, default: false },

  otp: { type: String, default: null },
  otpExpires: { type: Date, default: null },
  otpAttempts: { type: Number, default: 0 },
  otpLastSentAt: { type: Date, default: null },

  apps: { type: [String], default: ['plc-simtel'] },
  lastLogin: { type: Date }
}, { timestamps: true });

module.exports = mongoose.models.User || mongoose.model('User', userSchema);