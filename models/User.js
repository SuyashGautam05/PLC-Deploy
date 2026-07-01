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
  password: { type: String, required: true }, // bcrypt hash, never store plain text
  role: { type: String, enum: ['admin', 'user'], default: 'user' },
  isActive: { type: Boolean, default: false } // admin must approve before login works
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);