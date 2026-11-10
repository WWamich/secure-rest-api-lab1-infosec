const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const escapeHtml = require('escape-html');

const db = require('./db');
const { signToken, authenticate } = require('./auth');

const app = express();

app.use(helmet());
app.use(express.json({ limit: '10kb' }));
app.use(rateLimit({ windowMs: 60 * 1000, limit: 100, standardHeaders: true, legacyHeaders: false }));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { msg: 'Too many login attempts, try again later' },
});

const findUserByName = db.prepare('SELECT id, username, password_hash FROM users WHERE username = ?');
const insertPost = db.prepare('INSERT INTO posts (content, author_id) VALUES (?, ?)');
const listPosts = db.prepare(`
  SELECT p.id, p.content, u.username AS author, p.created_at
  FROM posts p
  JOIN users u ON u.id = p.author_id
  ORDER BY p.id DESC
  LIMIT 100
`);

const DUMMY_HASH = bcrypt.hashSync('dummy-password', 12);

app.post('/auth/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body ?? {};

  if (
    typeof username !== 'string' || typeof password !== 'string' ||
    !username || !password || username.length > 64 || password.length > 72
  ) {
    return res.status(400).json({ msg: 'username and password are required (strings)' });
  }

  const user = findUserByName.get(username);
  const ok = await bcrypt.compare(password, user ? user.password_hash : DUMMY_HASH);

  if (!user || !ok) {
    return res.status(401).json({ msg: 'Invalid credentials' });
  }

  return res.json({ access_token: signToken(user), token_type: 'Bearer', expires_in: 3600 });
});

app.get('/api/data', authenticate, (req, res) => {
  const posts = listPosts.all().map((p) => ({
    id: p.id,
    content: escapeHtml(p.content),
    author: escapeHtml(p.author),
    created_at: p.created_at,
  }));
  res.json({ posts });
});


app.post('/api/ping', (req, res) => {
  const { message } = req.body ?? {};

  if (message === 'ping') {
    return res.json({ reply: 'pong' });
  }
  return res.status(400).json({ msg: 'Send {"message": "ping"}' });
});

app.post('/api/posts', authenticate, (req, res) => {
  const { content } = req.body ?? {};

  if (typeof content !== 'string' || !content.trim()) {
    return res.status(400).json({ msg: 'Content is required' });
  }
  if (content.length > 500) {
    return res.status(400).json({ msg: 'Content is too long (max 500)' });
  }

  const info = insertPost.run(content.trim(), req.user.id);
  return res.status(201).json({ msg: 'Post created successfully', id: Number(info.lastInsertRowid) });
});

app.use((req, res) => res.status(404).json({ msg: 'Not found' }));

app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ msg: 'Invalid JSON' });
  }
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ msg: 'Payload too large' });
  }
  console.error(err);
  return res.status(500).json({ msg: 'Internal server error' });
});

module.exports = app;
