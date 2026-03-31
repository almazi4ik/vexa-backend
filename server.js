const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/vexa';
mongoose.connect(MONGODB_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB error:', err));

// СХЕМЫ
const userSchema = new mongoose.Schema({
  userID: { type: String, unique: true, default: () => new mongoose.Types.ObjectId().toString() },
  displayName: String,
  username: { type: String, unique: true, lowercase: true },
  email: { type: String, unique: true },
  password: String,
  bio: { type: String, default: '' },
  avatar: { type: String, default: '' },
  lastSeen: { type: Date, default: Date.now },
  isOnline: { type: Boolean, default: false },
  friends: [{ type: String }],
  customNames: { type: Map, of: String, default: {} }
});

const messageSchema = new mongoose.Schema({
  from: String,
  to: String,
  text: String,
  createdAt: { type: Date, default: Date.now },
  isRead: { type: Boolean, default: false }
});

const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);

// MIDDLEWARE
const auth = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Нет токена' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret_key');
    req.userId = decoded.userId;
    await User.findOneAndUpdate({ userID: req.userId }, { lastSeen: new Date(), isOnline: true });
    next();
  } catch {
    res.status(401).json({ error: 'Неверный токен' });
  }
};

// МАРШРУТЫ

// Регистрация
app.post('/api/auth/register', async (req, res) => {
  try {
    const { displayName, username, email, password } = req.body;
    const emailRegex = /^[^\s@]+@([^\s@]+\.)+[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Введите настоящий email (пример: name@mail.com)' });
    }
    const existing = await User.findOne({ $or: [{ email }, { username }] });
    if (existing) return res.status(400).json({ error: 'Email или username уже занят' });
    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ displayName, username: username.toLowerCase(), email, password: hashed });
    await user.save();
    const token = jwt.sign({ userId: user.userID }, process.env.JWT_SECRET || 'secret_key');
    res.json({ user: user.toObject(), token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Логин
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(401).json({ error: 'Неверные данные' });
    await User.findOneAndUpdate({ userID: user.userID }, { isOnline: true, lastSeen: new Date() });
    const token = jwt.sign({ userId: user.userID }, process.env.JWT_SECRET || 'secret_key');
    res.json({ user: user.toObject(), token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Выход
app.post('/api/auth/logout', auth, async (req, res) => {
  await User.findOneAndUpdate({ userID: req.userId }, { isOnline: false });
  res.json({ ok: true });
});

// Получить всех пользователей
app.get('/api/users', auth, async (req, res) => {
  const users = await User.find({}, '-password');
  res.json(users);
});

// Обновить профиль
app.put('/api/users/profile', auth, async (req, res) => {
  const { displayName, username, bio, avatar } = req.body;
  const existing = await User.findOne({ username, userID: { $ne: req.userId } });
  if (existing) return res.status(400).json({ error: 'Username уже занят' });
  const update = { displayName, username: username.toLowerCase(), bio };
  if (avatar !== undefined) update.avatar = avatar;
  const user = await User.findOneAndUpdate({ userID: req.userId }, update, { new: true }).select('-password');
  res.json(user);
});

// Добавить/удалить друга
app.post('/api/users/friends', auth, async (req, res) => {
  const { friendId, action } = req.body;
  const user = await User.findOne({ userID: req.userId });
  if (action === 'add' && !user.friends.includes(friendId)) {
    user.friends.push(friendId);
  } else if (action === 'remove') {
    user.friends = user.friends.filter(id => id !== friendId);
  }
  await user.save();
  res.json({ friends: user.friends });
});

// Установить своё имя для друга
app.post('/api/users/custom-name', auth, async (req, res) => {
  const { friendId, customName } = req.body;
  const user = await User.findOne({ userID: req.userId });
  if (!user.customNames) user.customNames = new Map();
  user.customNames.set(friendId, customName);
  await user.save();
  res.json({ customNames: Object.fromEntries(user.customNames) });
});

// Получить сообщения
app.get('/api/messages', auth, async (req, res) => {
  const msgs = await Message.find({ $or: [{ from: req.userId }, { to: req.userId }] });
  res.json(msgs);
});

// Отправить сообщение
app.post('/api/messages', auth, async (req, res) => {
  const { to, text } = req.body;
  if (to === req.userId) {
    const msg = new Message({ from: req.userId, to: req.userId, text });
    await msg.save();
    return res.json(msg);
  }
  const user = await User.findOne({ userID: req.userId });
  const isFriend = user.friends.includes(to);
  if (!isFriend) {
    const lastFromReceiver = await Message.findOne({ from: to, to: req.userId }).sort({ createdAt: -1 });
    const lastFromMe = await Message.findOne({ from: req.userId, to }).sort({ createdAt: -1 });
    if (lastFromMe && (!lastFromReceiver || lastFromReceiver.createdAt < lastFromMe.createdAt)) {
      return res.status(400).json({ error: 'Пользователь должен ответить на ваше предыдущее сообщение' });
    }
  }
  const msg = new Message({ from: req.userId, to, text });
  await msg.save();
  res.json(msg);
});

// Отметить сообщения как прочитанные
app.post('/api/messages/read', auth, async (req, res) => {
  const { from } = req.body;
  await Message.updateMany({ from: from, to: req.userId, isRead: false }, { isRead: true });
  res.json({ ok: true });
});

// Получить статусы пользователей
app.get('/api/status', auth, async (req, res) => {
  const users = await User.find({}, 'userID isOnline lastSeen');
  res.json(users);
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
