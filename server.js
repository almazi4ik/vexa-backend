const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

const auth = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Нет токена' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret_key');
    req.userId = decoded.userId;
    await supabase
      .from('users')
      .update({ lastseen: new Date(), isonline: true })
      .eq('userid', req.userId);
    next();
  } catch {
    res.status(401).json({ error: 'Неверный токен' });
  }
};

// Регистрация
app.post('/api/auth/register', async (req, res) => {
  try {
    const { displayName, username, email, password } = req.body;
    const emailRegex = /^[^\s@]+@([^\s@]+\.)+[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Введите настоящий email' });
    }
    const { data: existing } = await supabase
      .from('users')
      .select('userid')
      .or(`email.eq.${email},username.eq.${username}`);
    if (existing && existing.length > 0) {
      return res.status(400).json({ error: 'Email или username уже занят' });
    }
    const hashed = await bcrypt.hash(password, 10);
    const userID = Date.now().toString();
    const { data: user, error } = await supabase
      .from('users')
      .insert([{
        userid: userID,
        displayname: displayName,
        username: username.toLowerCase(),
        email,
        password: hashed,
        bio: '',
        avatar: '',
        friends: [],
        customnames: {}
      }])
      .select()
      .single();
    if (error) throw error;
    const token = jwt.sign({ userId: user.userid }, process.env.JWT_SECRET || 'secret_key');
    delete user.password;
    res.json({ user, token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Логин
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single();
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Неверные данные' });
    }
    await supabase
      .from('users')
      .update({ isonline: true, lastseen: new Date() })
      .eq('userid', user.userid);
    const token = jwt.sign({ userId: user.userid }, process.env.JWT_SECRET || 'secret_key');
    delete user.password;
    res.json({ user, token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Остальные маршруты (выход, пользователи, профиль, друзья, сообщения) — нужно везде использовать маленькие буквы: userid, displayname, customnames, isonline, lastseen, createdat, isread

app.post('/api/auth/logout', auth, async (req, res) => {
  await supabase.from('users').update({ isonline: false }).eq('userid', req.userId);
  res.json({ ok: true });
});

app.get('/api/users', auth, async (req, res) => {
  const { data: users, error } = await supabase
    .from('users')
    .select('userid, displayname, username, bio, avatar, lastseen, isonline, friends, customnames');
  if (error) return res.status(500).json({ error: error.message });
  res.json(users);
});

app.put('/api/users/profile', auth, async (req, res) => {
  const { displayName, username, bio, avatar } = req.body;
  const { data: existing } = await supabase
    .from('users')
    .select('userid')
    .eq('username', username)
    .neq('userid', req.userId);
  if (existing && existing.length > 0) {
    return res.status(400).json({ error: 'Username уже занят' });
  }
  const update = { displayname: displayName, username: username.toLowerCase(), bio };
  if (avatar !== undefined) update.avatar = avatar;
  const { data: user, error } = await supabase
    .from('users')
    .update(update)
    .eq('userid', req.userId)
    .select()
    .single();
  if (error) return res.status(500).json({ error: error.message });
  delete user.password;
  res.json(user);
});

app.post('/api/users/friends', auth, async (req, res) => {
  const { friendId, action } = req.body;
  const { data: user } = await supabase
    .from('users')
    .select('friends')
    .eq('userid', req.userId)
    .single();
  let friends = user.friends || [];
  if (action === 'add' && !friends.includes(friendId)) {
    friends.push(friendId);
  } else if (action === 'remove') {
    friends = friends.filter(id => id !== friendId);
  }
  await supabase.from('users').update({ friends }).eq('userid', req.userId);
  res.json({ friends });
});

app.post('/api/users/custom-name', auth, async (req, res) => {
  const { friendId, customName } = req.body;
  const { data: user } = await supabase
    .from('users')
    .select('customnames')
    .eq('userid', req.userId)
    .single();
  let customnames = user.customnames || {};
  customnames[friendId] = customName;
  await supabase.from('users').update({ customnames }).eq('userid', req.userId);
  res.json({ customnames });
});

app.get('/api/messages', auth, async (req, res) => {
  const { data: messages, error } = await supabase
    .from('messages')
    .select('*')
    .or(`from_user.eq.${req.userId},to_user.eq.${req.userId}`);
  if (error) return res.status(500).json({ error: error.message });
  res.json(messages.map(m => ({
    id: m.id,
    from: m.from_user,
    to: m.to_user,
    text: m.text,
    createdAt: m.createdat,
    isRead: m.isread
  })));
});

app.post('/api/messages', auth, async (req, res) => {
  const { to, text } = req.body;
  const { data: user } = await supabase
    .from('users')
    .select('friends')
    .eq('userid', req.userId)
    .single();
  const isFriend = user.friends?.includes(to);
  if (!isFriend && to !== req.userId) {
    const { data: lastFromReceiver } = await supabase
      .from('messages')
      .select('*')
      .eq('from_user', to)
      .eq('to_user', req.userId)
      .order('createdat', { ascending: false })
      .limit(1);
    const { data: lastFromMe } = await supabase
      .from('messages')
      .select('*')
      .eq('from_user', req.userId)
      .eq('to_user', to)
      .order('createdat', { ascending: false })
      .limit(1);
    if (lastFromMe && lastFromMe.length > 0 && (!lastFromReceiver || lastFromReceiver.length === 0 || lastFromReceiver[0].createdat < lastFromMe[0].createdat)) {
      return res.status(400).json({ error: 'Пользователь должен ответить на ваше предыдущее сообщение' });
    }
  }
  const { data: msg, error } = await supabase
    .from('messages')
    .insert([{ from_user: req.userId, to_user: to, text }])
    .select()
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json({
    id: msg.id,
    from: msg.from_user,
    to: msg.to_user,
    text: msg.text,
    createdAt: msg.createdat,
    isRead: msg.isread
  });
});

app.post('/api/messages/read', auth, async (req, res) => {
  const { from } = req.body;
  await supabase
    .from('messages')
    .update({ isread: true })
    .eq('from_user', from)
    .eq('to_user', req.userId)
    .eq('isread', false);
  res.json({ ok: true });
});

app.get('/api/status', auth, async (req, res) => {
  const { data: users, error } = await supabase
    .from('users')
    .select('userid, isonline, lastseen');
  if (error) return res.status(500).json({ error: error.message });
  res.json(users);
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
