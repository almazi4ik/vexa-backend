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

// ========== АВТОРИЗАЦИЯ ==========
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

app.post('/api/auth/logout', auth, async (req, res) => {
  await supabase.from('users').update({ isonline: false }).eq('userid', req.userId);
  res.json({ ok: true });
});

// ========== ПОЛЬЗОВАТЕЛИ ==========
app.get('/api/users', auth, async (req, res) => {
  const { data: users, error } = await supabase
    .from('users')
    .select('userid, displayname, username, bio, avatar, lastseen, isonline');
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

// ========== ЛИЧНЫЕ СООБЩЕНИЯ ==========
app.get('/api/messages', auth, async (req, res) => {
  const { data: messages, error } = await supabase
    .from('messages')
    .select('*')
    .or(`from_user.eq.${req.userId},to_user.eq.${req.userId}`)
    .is('group_id', null);
  if (error) return res.status(500).json({ error: error.message });
  res.json(messages);
});

app.post('/api/messages', auth, async (req, res) => {
  const { to, text, image } = req.body;
  const { data: msg, error } = await supabase
    .from('messages')
    .insert([{ from_user: req.userId, to_user: to, text, image, is_group: false }])
    .select()
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(msg);
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

app.put('/api/messages/:id', auth, async (req, res) => {
  const { id } = req.params;
  const { text } = req.body;
  await supabase.from('messages').update({ text }).eq('id', id);
  res.json({ ok: true });
});

app.delete('/api/messages/:id', auth, async (req, res) => {
  const { id } = req.params;
  await supabase.from('messages').delete().eq('id', id);
  res.json({ ok: true });
});

app.delete('/api/messages/clear/:userId', auth, async (req, res) => {
  const { userId } = req.params;
  await supabase
    .from('messages')
    .delete()
    .or(`and(from_user.eq.${req.userId},to_user.eq.${userId}),and(from_user.eq.${userId},to_user.eq.${req.userId})`);
  res.json({ ok: true });
});

// ========== ГРУППЫ ==========
app.get('/api/groups', auth, async (req, res) => {
  const { data: groups, error } = await supabase
    .from('groups')
    .select('*');
  if (error) return res.status(500).json({ error: error.message });
  res.json(groups);
});

app.post('/api/groups', auth, async (req, res) => {
  const { name, description, avatar } = req.body;
  const { data: group, error } = await supabase
    .from('groups')
    .insert([{ name, description, avatar, owner_id: req.userId }])
    .select()
    .single();
  if (error) return res.status(500).json({ error: error.message });
  await supabase
    .from('group_members')
    .insert([{ group_id: group.id, user_id: req.userId, role: 'owner' }]);
  res.json(group);
});

app.get('/api/groups/:id/members', auth, async (req, res) => {
  const { id } = req.params;
  const { data: members, error } = await supabase
    .from('group_members')
    .select('user_id, role, joined_at')
    .eq('group_id', id);
  if (error) return res.status(500).json({ error: error.message });
  res.json(members);
});

app.post('/api/groups/:id/members', auth, async (req, res) => {
  const { id } = req.params;
  const { userId } = req.body;
  const { data: existing } = await supabase
    .from('group_members')
    .select('*')
    .eq('group_id', id)
    .eq('user_id', userId);
  if (existing && existing.length > 0) return res.json({ ok: true });
  await supabase
    .from('group_members')
    .insert([{ group_id: id, user_id: userId, role: 'member' }]);
  res.json({ ok: true });
});

app.delete('/api/groups/:id/members/:userId', auth, async (req, res) => {
  const { id, userId } = req.params;
  await supabase
    .from('group_members')
    .delete()
    .eq('group_id', id)
    .eq('user_id', userId);
  res.json({ ok: true });
});

app.get('/api/groups/:id/messages', auth, async (req, res) => {
  const { id } = req.params;
  const { data: messages, error } = await supabase
    .from('messages')
    .select('*')
    .eq('group_id', id)
    .eq('is_group', true)
    .order('createdat', { ascending: true });
  if (error) return res.status(500).json({ error: error.message });
  res.json(messages);
});

app.post('/api/groups/:id/messages', auth, async (req, res) => {
  const { id } = req.params;
  const { text, image } = req.body;
  const { data: msg, error } = await supabase
    .from('messages')
    .insert([{ from_user: req.userId, text, image, is_group: true, group_id: id }])
    .select()
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(msg);
});

// ========== БАНЫ ==========
app.post('/api/bans', auth, async (req, res) => {
  const { userId, reason } = req.body;
  await supabase
    .from('banned_users')
    .insert([{ user_id: userId, banned_by: req.userId, reason }]);
  res.json({ ok: true });
});

app.delete('/api/bans/:userId', auth, async (req, res) => {
  const { userId } = req.params;
  await supabase
    .from('banned_users')
    .delete()
    .eq('user_id', userId)
    .eq('banned_by', req.userId);
  res.json({ ok: true });
});

app.get('/api/bans', auth, async (req, res) => {
  const { data: bans, error } = await supabase
    .from('banned_users')
    .select('*')
    .eq('banned_by', req.userId);
  if (error) return res.status(500).json({ error: error.message });
  res.json(bans);
});

// ========== СТАТУСЫ ==========
app.get('/api/status', auth, async (req, res) => {
  const { data: users, error } = await supabase
    .from('users')
    .select('userid, isonline, lastseen');
  if (error) return res.status(500).json({ error: error.message });
  res.json(users);
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
