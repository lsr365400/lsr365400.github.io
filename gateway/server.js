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

// Request logging — log ALL requests including headers for auth debug
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    console.log(`${res.statusCode} ${req.method} ${req.path} auth=${req.headers.authorization ? 'Bearer' : 'none'} (${Date.now() - start}ms)`);
  });
  next();
});

// No cache for API
app.use((req, res, next) => {
  if (req.path.startsWith('/.')) {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
  }
  next();
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.get('/', (req, res) => res.redirect('/admin/'));
// Serve admin page with embedded auth token
app.use('/admin', (req, res, next) => {
  if (req.path === '/' || req.path === '') {
    // Generate a fresh token for the admin page
    const token = generateJWT(CONFIG.username);
    const gotrueUser = JSON.stringify({
      url: '/.netlify/identity',
      token: {
        access_token: token,
        token_type: 'bearer',
        expires_in: 86400,
        refresh_token: token,
        user: { id: CONFIG.username, email: CONFIG.username, app_metadata: { provider: 'email', hasWriteAccess: true }, user_metadata: {}, hasWriteAccess: true },
      },
      id: CONFIG.username,
      email: CONFIG.username,
      app_metadata: { provider: 'email', hasWriteAccess: true },
      user_metadata: {},
      hasWriteAccess: true,
      expires_at: Date.now() + 86400000,
    });
    const html = require('fs').readFileSync(path.join(__dirname, 'admin', 'index.html'), 'utf8');
    const injected = html.replace('</head>', `<script>localStorage.setItem('gotrue.user','${gotrueUser.replace(/'/g, "\\'")}');</script></head>`);
    res.type('html').send(injected);
  } else {
    next();
  }
}, express.static(path.join(__dirname, 'admin'), { index: false }));

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
    user: { id: username, email: username, app_metadata: { provider: 'email', hasWriteAccess: true }, user_metadata: {}, hasWriteAccess: true },
  });
});

app.get('/.netlify/git/settings', (req, res) => {
  res.json({
    git_gateway: {
      hasWriteAccess: true,
    },
    hasWriteAccess: true,
    write_access: true,
    auth_required: true,
    base_url: '/.netlify/git/github',
  });
});

app.get('/.netlify/identity/user', (req, res) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const p = jwt.verify(auth.slice(7), CONFIG.jwtSecret);
    return res.json({ id: p.sub, email: p.sub, app_metadata: { provider: 'email', hasWriteAccess: true }, user_metadata: {}, hasWriteAccess: true });
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

// Handle /repositories/ endpoint (CMS checks write access here)
app.all('/.netlify/git/github/repositories/*', checkAuth, (req, res) => {
  const repo = req.path.replace(/^\/\.netlify\/git\/github\/repositories\//, '');
  const url = `https://api.github.com/repos/${repo}`;
  const headers = {
    'Authorization': `token ${CONFIG.githubToken}`,
    'Accept': 'application/vnd.github.v3+json',
    'User-Agent': 'blog-gateway/1.0',
  };
  https.get(url, { headers }, (rr) => {
    let d = '';
    rr.on('data', c => d += c);
    rr.on('end', () => {
      try {
        const repoData = JSON.parse(d);
        res.json({
          owner: { login: repoData.owner?.login || 'lsr365400' },
          permissions: { push: true, admin: true, pull: true },
          name: repoData.name,
          full_name: repoData.full_name,
        });
      } catch (e) {
        res.json({ owner: { login: 'lsr365400' }, permissions: { push: true, admin: true, pull: true } });
      }
    });
  }).on('error', () => {
    res.json({ owner: { login: 'lsr365400' }, permissions: { push: true, admin: true, pull: true } });
  });
});

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
