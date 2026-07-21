// backend/server.js
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { spawn } = require('child_process');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// Rate Limiter
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Terlalu banyak permintaan, coba lagi nanti.'
});
app.use('/api/', limiter);

// Koneksi MongoDB
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/ml_legacy', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

// =============== SCHEMA ===============
const AccountSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  moontonId: { type: String, required: true },
  level: { type: Number, required: true },
  rank: { type: String, enum: ['Warrior', 'Elite', 'Master', 'Grandmaster', 'Epic', 'Legend', 'Mythic', 'Mythical Glory'] },
  heroes: [{ 
    name: String, 
    mastery: Number,
    matches: Number,
    winrate: Number
  }],
  totalMatches: Number,
  winRate: Number,
  lastLogin: Date,
  offlineSince: Date,
  status: { 
    type: String, 
    enum: ['available', 'claimed', 'pending', 'inactive'],
    default: 'available'
  },
  claimedAt: Date,
  claimedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  verified: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const UserSchema = new mongoose.Schema({
  moontonEmail: { type: String, required: true, unique: true },
  moontonPassword: { type: String, required: true },
  username: { type: String, required: true },
  claimedAccounts: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Account' }],
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  createdAt: { type: Date, default: Date.now }
});

const Account = mongoose.model('Account', AccountSchema);
const User = mongoose.model('User', UserSchema);

// =============== MIDDLEWARE ===============
const authenticate = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token diperlukan' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secretkey');
    const user = await User.findById(decoded.userId);
    if (!user) return res.status(401).json({ error: 'User tidak ditemukan' });
    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Token tidak valid' });
  }
};

// =============== API ENDPOINTS ===============

// Register
app.post('/api/auth/register', async (req, res) => {
  const { moontonEmail, moontonPassword, username } = req.body;

  try {
    const existingUser = await User.findOne({ moontonEmail });
    if (existingUser) {
      return res.status(400).json({ error: 'Akun Moonton sudah terdaftar' });
    }

    const user = new User({
      moontonEmail,
      moontonPassword: bcrypt.hashSync(moontonPassword, 10),
      username
    });

    await user.save();

    const token = jwt.sign(
      { userId: user._id, email: user.moontonEmail },
      process.env.JWT_SECRET || 'secretkey',
      { expiresIn: '7d' }
    );

    res.json({ 
      success: true, 
      token, 
      user: { 
        id: user._id, 
        username: user.username, 
        email: user.moontonEmail 
      } 
    });
  } catch (error) {
    res.status(500).json({ error: 'Terjadi kesalahan server' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { moontonEmail, moontonPassword } = req.body;

  try {
    const user = await User.findOne({ moontonEmail });
    if (!user) {
      return res.status(401).json({ error: 'Email tidak terdaftar' });
    }

    const validPassword = bcrypt.compareSync(moontonPassword, user.moontonPassword);
    if (!validPassword) {
      return res.status(401).json({ error: 'Password salah' });
    }

    const token = jwt.sign(
      { userId: user._id, email: user.moontonEmail },
      process.env.JWT_SECRET || 'secretkey',
      { expiresIn: '7d' }
    );

    res.json({ 
      success: true, 
      token, 
      user: { 
        id: user._id, 
        username: user.username, 
        email: user.moontonEmail 
      } 
    });
  } catch (error) {
    res.status(500).json({ error: 'Terjadi kesalahan server' });
  }
});

// Get available accounts
app.get('/api/accounts', authenticate, async (req, res) => {
  try {
    const { page = 1, limit = 20, minLevel = 0, rank } = req.query;
    const query = { status: 'available' };

    if (minLevel) query.level = { $gte: parseInt(minLevel) };
    if (rank) query.rank = rank;

    const accounts = await Account.find(query)
      .sort({ level: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await Account.countDocuments(query);

    const sanitizedAccounts = accounts.map(acc => ({
      id: acc._id,
      username: acc.username,
      level: acc.level,
      rank: acc.rank,
      heroes: acc.heroes.slice(0, 5),
      totalMatches: acc.totalMatches,
      winRate: acc.winRate,
      offlineSince: acc.offlineSince,
      verified: acc.verified
    }));

    res.json({
      accounts: sanitizedAccounts,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      totalAccounts: total
    });
  } catch (error) {
    res.status(500).json({ error: 'Gagal mengambil data akun' });
  }
});

// Claim account
app.post('/api/accounts/:id/claim', authenticate, async (req, res) => {
  try {
    const account = await Account.findById(req.params.id);
    if (!account) {
      return res.status(404).json({ error: 'Akun tidak ditemukan' });
    }

    if (account.status !== 'available') {
      return res.status(400).json({ error: 'Akun sudah diambil orang lain' });
    }

    const userAccounts = await Account.countDocuments({
      claimedBy: req.user._id,
      status: 'claimed'
    });

    if (userAccounts >= 3) {
      return res.status(400).json({ error: 'Maksimal 3 akun per user' });
    }

    account.status = 'claimed';
    account.claimedAt = new Date();
    account.claimedBy = req.user._id;
    await account.save();

    req.user.claimedAccounts.push(account._id);
    await req.user.save();

    res.json({
      success: true,
      message: 'Berhasil mengklaim akun!',
      account: {
        id: account._id,
        username: account.username,
        password: account.password,
        moontonId: account.moontonId,
        level: account.level,
        rank: account.rank
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Gagal mengklaim akun' });
  }
});

// Get user's claimed accounts
app.get('/api/me/accounts', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).populate('claimedAccounts');
    res.json({ accounts: user.claimedAccounts || [] });
  } catch (error) {
    res.status(500).json({ error: 'Gagal mengambil akun Anda' });
  }
});

// =============== START SERVER ===============
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server berjalan di port ${PORT}`);
});
