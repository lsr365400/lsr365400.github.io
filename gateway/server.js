require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const https = require('https');
const path = require('path');

const CONFIG = {
  port: process.env.PORT || 3000,
  username: process.env.ADMIN_USER || 'admin',
  passwordHash: process.env.ADMIN_PASS_HASH || '',
  githubToken: process.env.GITHUB_TOKEN || '',
  jwtSecret: process.env.SESSION_SECRET || 'change-me',
};

const app = express();

// Request logging
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    console.log(`${res.statusCode} ${req.method} ${req.path} (${Date.now() - start}ms)`);
  });
  next();
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.get('/', (req, res) => res.redirect('/admin/'));
app.use('/admin', express.static(path.join(__dirname, 'admin'), { index: 'index.html' }));

// ---- Token ----

function generateJWT(username) {
  return jwt.sign(
    {
      sub: username,
      email: username,
      exp: Math.floor(Date.now() / 1000) + 86400,
      app_metadata: { provider: 'email' },
      user_metadata: {},
    },
    CONFIG.jwtSecret,
  );
}

function checkAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (auth && auth.startsWith('Bearer ')) {
    try {
      jwt.verify(auth.slice(7), CONFIG.jwtSecret);
      return next();
    } catch (e) { /* invalid */ }
  }
  res.status(401).json({ error: 'Unauthorized' });
}

// ---- Token endpoint (for Decap CMS login) ----

app.post('/.netlify/identity/token', (req, res) => {
  const { username, password, grant_type } = req.body;
  if (!grant_type || !username || !password) {
    return res.status(400).json({ error: 'invalid_grant' });
  }
  if (username !== CONFIG.username || !bcrypt.compareSync(password, CONFIG.passwordHash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = generateJWT(username);
  res.json({
    access_token: token,
    token_type: 'bearer',
    expires_in: 86400,
    refresh_token: token,
    user: { id: username, email: username, app_metadata: { provider: 'email' }, user_metadata: {} },
  });
});

app.get('/.netlify/git/settings', (req, res) => {
  res.json({ base_url: '', provider: 'github' });
});

app.get('/.netlify/identity/user', (req, res) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const p = jwt.verify(auth.slice(7), CONFIG.jwtSecret);
    return res.json({ id: p.sub, email: p.sub, app_metadata: { provider: 'email' }, user_metadata: {} });
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
});

app.post('/.netlify/identity/refresh', (req, res) => {
  const t = (req.headers.authorization || '').replace('Bearer ', '');
  try {
    const p = jwt.verify(t, CONFIG.jwtSecret);
    const nt = generateJWT(p.sub);
    return res.json({ access_token: nt, token_type: 'bearer', expires_in: 86400, refresh_token: nt });
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
});

// ---- GitHub API proxy ----

app.all(['/github/*', '/.netlify/git/github/*'], checkAuth, (req, res) => {
  let p = req.path;
  p = p.replace(/^\/\.netlify\/git\/github/, '');
  p = p.replace(/^\/github/, '');
  const url = `https://api.github.com${p}`;

  const headers = {
    'Authorization': `token ${CONFIG.githubToken}`,
    'Accept': 'application/vnd.github.v3+json',
    'User-Agent': 'blog-gateway/1.0',
  };
  if (req.headers['content-type']) headers['Content-Type'] = req.headers['content-type'];

  const body = ['GET','HEAD'].includes(req.method) ? null :
    (req.body && Object.keys(req.body).length ? JSON.stringify(req.body) : null);
  if (body) headers['Content-Length'] = Buffer.byteLength(body);

  const r = https.request(url, { method: req.method, headers }, (rr) => {
    let d = '';
    rr.on('data', c => d += c);
    rr.on('end', () => {
      res.status(rr.statusCode);
      if (rr.headers['content-type']) res.set('Content-Type', rr.headers['content-type']);
      res.send(d);
    });
  });
  r.on('error', e => res.status(502).json({ error: e.message }));
  if (body) r.write(body);
  r.end();
});

app.listen(CONFIG.port, () => {
  console.log(`Blog gateway running on :${CONFIG.port}`);
});
