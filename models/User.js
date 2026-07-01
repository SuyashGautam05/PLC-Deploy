const mongoose = require('mongoose');

const GMAIL_REGEX = /^[a-zA-Z0-9](?:[a-zA-Z0-9.]{0,63})@gmail\.com$/;

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    validate: {
      validator: (v) => GMAIL_REGEX.test(v),
      message: (props) => `${props.value} is not a valid @gmail.com address.`
    }
  },
  password: { type: String, required: true }, // bcrypt hash
  role: { type: String, enum: ['admin', 'user'], default: 'user' },

  // isActive = true only after the USER verifies their own email via OTP.
  // Admin can still manually flip this off later to revoke access.
  isActive: { type: Boolean, default: false },

  otp: { type: String, default: null },       // bcrypt-hashed OTP, never stored in plain text
  otpExpires: { type: Date, default: null }
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);