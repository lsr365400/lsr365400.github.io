require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const https = require('https');
const path = require('path');

const CONFIG = {
  port: process.env.PORT || 3000,
  username: process.env.ADMIN_USER || 'admin',
  passwordHash: process.env.ADMIN_PASS_HASH || '',
  githubToken: process.env.GITHUB_TOKEN || '',
  sessionSecret: process.env.SESSION_SECRET || 'change-me',
};

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: CONFIG.sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 24 * 60 * 60 * 1000 },
}));

// ---- Token auth (JWT for Decap CMS git-gateway) ----

function generateJWT(username) {
  return jwt.sign(
    {
      sub: username,
      email: username,
      exp: Math.floor(Date.now() / 1000) + 86400,
      app_metadata: { provider: 'email' },
      user_metadata: {},
    },
    CONFIG.sessionSecret,
  );
}

function checkAuth(req, res, next) {
  // Session-based
  if (req.session && req.session.user) return next();
  // Token-based (Bearer)
  const auth = req.headers.authorization;
  if (auth && auth.startsWith('Bearer ')) {
    try {
      const payload = jwt.verify(auth.slice(7), CONFIG.sessionSecret);
      req.session = req.session || {};
      req.session.user = payload.sub;
      return next();
    } catch (e) { /* invalid token */ }
  }
  if (req.accepts('html')) return res.redirect(`/login?next=${encodeURIComponent(req.originalUrl)}`);
  res.status(401).json({ error: 'Unauthorized' });
}

// ---- Netlify Identity compatible token endpoint ----

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

app.post('/.netlify/identity/refresh', (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  try {
    const payload = jwt.verify(token, CONFIG.sessionSecret);
    const newToken = generateJWT(payload.sub);
    return res.json({ access_token: newToken, token_type: 'bearer', expires_in: 86400, refresh_token: newToken });
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
});

// ---- login page ----

app.get('/login', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Blog Admin Login</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{display:flex;align-items:center;justify-content:center;min-height:100vh;background:#1a1a2e;font-family:-apple-system,system-ui,sans-serif}
form{background:#16213e;padding:40px;border-radius:12px;width:360px;box-shadow:0 20px 60px rgba(0,0,0,.3)}
h1{color:#e94560;text-align:center;margin-bottom:32px;font-size:24px}
label{color:#a0a0b0;font-size:13px;display:block;margin-bottom:6px}
input{width:100%;padding:12px;border:1px solid #2a2a4a;border-radius:8px;background:#0f3460;color:#fff;font-size:15px;margin-bottom:20px;outline:none}
input:focus{border-color:#e94560}
button{width:100%;padding:12px;background:#e94560;color:#fff;border:none;border-radius:8px;font-size:16px;cursor:pointer;font-weight:600}
button:hover{background:#d63850}
.error{color:#e94560;text-align:center;margin-bottom:16px;font-size:14px}
</style>
</head>
<body>
<form method="post" action="/login">
  <h1>博客管理</h1>
  {{error}}
  <label>用户名</label>
  <input name="username" type="text" required autofocus>
  <label>密码</label>
  <input name="password" type="password" required>
  <button type="submit">登录</button>
</form>
</body>
</html>`.replace('{{error}}', req.query.error ? '<p class="error">用户名或密码错误</p>' : ''));
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.redirect('/login?error=1');
  if (username !== CONFIG.username || !bcrypt.compareSync(password, CONFIG.passwordHash)) {
    return res.redirect('/login?error=1');
  }
  req.session.user = username;
  const token = generateJWT(username);
  res.redirect(`/admin/?token=${encodeURIComponent(token)}`);
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// ---- admin page ----

app.use('/admin', checkAuth, express.static(path.join(__dirname, 'admin')));

// ---- GitHub API proxy ----

app.all(['/github/*', '/.netlify/git/github/*'], checkAuth, (req, res) => {
  let ghPath = req.path;
  ghPath = ghPath.replace(/^\/\.netlify\/git\/github/, '');
  ghPath = ghPath.replace(/^\/github/, '');
  const ghUrl = `https://api.github.com${ghPath}`;

  const headers = {
    'Authorization': `token ${CONFIG.githubToken}`,
    'Accept': 'application/vnd.github.v3+json',
    'User-Agent': 'blog-gateway/1.0',
  };
  if (req.headers['content-type']) headers['Content-Type'] = req.headers['content-type'];

  const body = ['GET','HEAD'].includes(req.method) ? null :
    (req.body && Object.keys(req.body).length ? JSON.stringify(req.body) : null);
  if (body) headers['Content-Length'] = Buffer.byteLength(body);

  const proxyReq = https.request(ghUrl, { method: req.method, headers }, (proxyRes) => {
    let data = '';
    proxyRes.on('data', chunk => data += chunk);
    proxyRes.on('end', () => {
      res.status(proxyRes.statusCode);
      const ct = proxyRes.headers['content-type'] || '';
      if (ct) res.set('Content-Type', ct);
      res.send(data);
    });
  });

  proxyReq.on('error', err => res.status(502).json({ error: err.message }));
  if (body) proxyReq.write(body);
  proxyReq.end();
});

app.listen(CONFIG.port, () => {
  console.log(`Blog gateway running on :${CONFIG.port}`);
});
