const express = require('express');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const { verifyToken, requireAdmin } = require('../middleware/auth');
const { isValidGmail } = require('../utils/validateEmail');

const router = express.Router();

// Every route below requires a valid admin token
router.use(verifyToken, requireAdmin);

// GET /api/admin/users
router.get('/users', async (req, res) => {
  try {
    const users = await User.find().select('-password').sort({ createdAt: -1 });
    res.json({ success: true, users });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error while fetching users.' });
  }
});

// POST /api/admin/users  body: { name, email, password, role }
// Admin manually creates + activates a user. Email must be a real @gmail.com address.
router.post('/users', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ success: false, message: 'Name, email and password are required.' });
    }

    if (password.length < 6) {
      return res.status(400).json({ success: false, message: 'Password must be at least 6 characters.' });
    }

    const normalizedEmail = email.trim().toLowerCase();

    if (!isValidGmail(normalizedEmail)) {
      return res.status(400).json({
        success: false,
        message: 'Only real @gmail.com addresses are allowed. Please enter a valid Gmail address.'
      });
    }

    const existing = await User.findOne({ email: normalizedEmail });
    if (existing) {
      return res.status(409).json({ success: false, message: 'A user with this email already exists.' });
    }

    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({
      name: name.trim(),
      email: normalizedEmail,
      password: hashed,
      role: role === 'admin' ? 'admin' : 'user',
      isActive: true // "Create & Activate" - admin is creating this user directly
    });

    const { password: _pw, ...safeUser } = user.toObject();
    res.status(201).json({ success: true, message: 'User created and activated.', user: safeUser });
  } catch (err) {
    console.error(err);
    if (err.name === 'ValidationError') {
      return res.status(400).json({ success: false, message: Object.values(err.errors)[0].message });
    }
    res.status(500).json({ success: false, message: 'Server error while creating user.' });
  }
});

// PUT /api/admin/users/:id/activate
router.put('/users/:id/activate', async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(req.params.id, { isActive: true }, { new: true }).select('-password');
    if (!user) return res.status(404).json({ success: false, message: 'User not found.' });
    res.json({ success: true, message: 'User activated.', user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error while activating user.' });
  }
});

// PUT /api/admin/users/:id/deactivate
router.put('/users/:id/deactivate', async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(req.params.id, { isActive: false }, { new: true }).select('-password');
    if (!user) return res.status(404).json({ success: false, message: 'User not found.' });
    res.json({ success: true, message: 'User deactivated.', user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error while deactivating user.' });
  }
});

// PUT /api/admin/users/:id/role  body: { role }
router.put('/users/:id/role', async (req, res) => {
  try {
    const { role } = req.body;
    if (role !== 'admin' && role !== 'user') {
      return res.status(400).json({ success: false, message: 'role must be "admin" or "user".' });
    }

    const user = await User.findByIdAndUpdate(req.params.id, { role }, { new: true }).select('-password');
    if (!user) return res.status(404).json({ success: false, message: 'User not found.' });
    res.json({ success: true, message: 'Role updated.', user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error while updating role.' });
  }
});

// DELETE /api/admin/users/:id
router.delete('/users/:id', async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) return res.status(404).json({ success: false, message: 'User not found.' });
    res.json({ success: true, message: 'User deleted.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error while deleting user.' });
  }
});

module.exports = router;