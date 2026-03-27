// ─────────────────────────────────────────────────────────────
// KidStrong QBO Journal Entry Server
// Full OAuth 2.0 Authorization Code Flow — no manual tokens
// Run: node server.js  →  opens http://localhost:3000
// ─────────────────────────────────────────────────────────────
const http  = require('http');
const https = require('https');
const fs    = require('fs');
const path  = require('path');
const url   = require('url');
const crypto = require('crypto');

const PORT         = 3000;
// Redirect URI — must match exactly what's registered in Intuit Developer Portal
// Development: http://localhost:3000/callback
// Production:  your GitHub Pages URL (set GITHUB_REDIRECT below after setup)
const GITHUB_REDIRECT = '';  // ← paste your GitHub Pages URL here after setup
                              //   e.g. 'https://yourusername.github.io/ks-auth'

function getRedirectUri() {
  if (state.environment === 'production' && GITHUB_REDIRECT) {
    return GITHUB_REDIRECT;
  }
  return `http://localhost:${PORT}/callback`;
}
const TOKEN_FILE   = path.join(__dirname, '.qbo_tokens.json');
const MAPPING_FILE = path.join(__dirname, '.qbo_mappings.json');
const HISTORY_FILE = path.join(__dirname, '.qbo_history.json');
const SCOPES       = 'com.intuit.quickbooks.accounting';

const QBO_HOST = {
  production: 'quickbooks.api.intuit.com',
  sandbox:    'sandbox-quickbooks.api.intuit.com',
};

// ── State ──
let state = {
  clientId:     '',
  clientSecret: '',
  environment:  'production',
  realmId:      '',
  accessToken:  '',
  refreshToken: '',
  tokenExpiry:  0,
  oauthState:   '',   // CSRF token for OAuth flow
  connected:    false,
};

// ── Load saved tokens on startup ──
function loadTokens() {
  try {
    if (fs.existsSync(TOKEN_FILE)) {
      const saved = JSON.parse(fs.readFileSync(TOKEN_FILE, 'utf8'));
      Object.assign(state, saved);
      console.log('✅ Loaded saved tokens. Realm ID:', state.realmId);
      state.connected = true;
    }
  } catch (e) {
    console.log('ℹ️  No saved tokens found — please connect via the dashboard.');
  }
}

function saveTokens() {
  const toSave = {
    clientId:     state.clientId,
    clientSecret: state.clientSecret,
    environment:  state.environment,
    realmId:      state.realmId,
    accessToken:  state.accessToken,
    refreshToken: state.refreshToken,
    tokenExpiry:  state.tokenExpiry,
  };
  fs.writeFileSync(TOKEN_FILE, JSON.stringify(toSave, null, 2));
}

// ── Main HTTP Server ──
const server = http.createServer(async (req, res) => {
  setCors(res);
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  const parsed   = url.parse(req.url, true);
  const pathname = parsed.pathname;

  // ── Serve dashboard ──
  if (pathname === '/' || pathname === '/index.html') {
    try {
      const html = fs.readFileSync(path.join(__dirname, 'dashboard.html'));
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
    } catch {
      res.writeHead(500); res.end('dashboard.html not found');
    }
    return;
  }

  // ── OAuth Callback — Intuit redirects here after login ──
  if (pathname === '/callback') {
    const { code, realmId, state: returnedState, error } = parsed.query;

    if (error) {
      console.error('❌ OAuth error from Intuit:', error);
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(callbackPage('error', `Intuit returned an error: ${error}`));
      return;
    }

    if (returnedState !== state.oauthState) {
      console.error('❌ OAuth state mismatch — possible CSRF');
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(callbackPage('error', 'Security check failed. Please try connecting again.'));
      return;
    }

    try {
      console.log('🔄 Exchanging auth code for tokens…');
      const tokens = await exchangeCode(code);
      state.accessToken  = tokens.access_token;
      state.refreshToken = tokens.refresh_token;
      state.tokenExpiry  = Date.now() + ((tokens.expires_in || 3600) - 60) * 1000;
      state.realmId      = realmId;
      state.connected    = true;
      saveTokens();
      console.log('✅ Tokens obtained and saved!');
      console.log('   Realm ID :', state.realmId);
      console.log('   Expires  :', Math.round((state.tokenExpiry - Date.now()) / 60000), 'min');
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(callbackPage('success', 'QuickBooks connected successfully! This window will close automatically.'));
    } catch (err) {
      console.error('❌ Token exchange error:', err.message);
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(callbackPage('error', err.message));
    }
    return;
  }

  // ── API Routes ──
  try {
    // Save credentials + return auth URL for browser to open
    if (pathname === '/api/start-auth' && req.method === 'POST') {
      const body = JSON.parse(await readBody(req));
      state.clientId     = body.clientId     || '';
      state.clientSecret = body.clientSecret || '';
      state.environment  = body.environment  || 'production';
      state.oauthState   = crypto.randomBytes(16).toString('hex');
      state.connected    = false;

      if (!state.clientId || !state.clientSecret) {
        json(res, 400, { error: 'Client ID and Client Secret are required.' });
        return;
      }

      const authUrl = buildAuthUrl();
      console.log('🔗 Auth URL generated. Waiting for browser login…');
      json(res, 200, { authUrl });
      return;
    }

    if (pathname === '/api/status' && req.method === 'GET') {
      json(res, 200, {
        connected:    state.connected,
        realmId:      state.realmId,
        environment:  state.environment,
        clientId:     state.clientId,
        clientSecret: state.clientSecret ? '••••••••' : '',   // masked — just signals it exists
        hasCreds:     !!(state.clientId && state.clientSecret),
      });
      return;
    }

    if (pathname === '/api/disconnect' && req.method === 'POST') {
      state.connected   = false;
      state.accessToken = '';
      state.refreshToken = '';
      state.realmId     = '';
      if (fs.existsSync(TOKEN_FILE)) fs.unlinkSync(TOKEN_FILE);
      console.log('🔌 Disconnected and tokens cleared.');
      json(res, 200, { success: true });
      return;
    }

    if (pathname === '/api/accounts' && req.method === 'GET') {
      await ensureToken();
      const data = await qboGet(`/v3/company/${state.realmId}/query?query=select%20*%20from%20Account&minorversion=75`);
      json(res, 200, data);
      return;
    }

    if (pathname === '/api/journalentry' && req.method === 'POST') {
      await ensureToken();
      const body = await readBody(req);
      const data = await qboPost(`/v3/company/${state.realmId}/journalentry?minorversion=75`, body);
      json(res, 200, data);
      return;
    }

    if (pathname === '/api/save-env' && req.method === 'POST') {
      const body = JSON.parse(await readBody(req));
      if (body.environment) {
        state.environment = body.environment;
        saveTokens();  // persist alongside other token data
        console.log('💾 Environment saved:', state.environment);
      }
      json(res, 200, { success: true });
      return;
    }

    if (pathname === '/api/mappings' && req.method === 'GET') {
      try {
        if (fs.existsSync(MAPPING_FILE)) {
          const data = fs.readFileSync(MAPPING_FILE, 'utf8');
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(data);
        } else {
          json(res, 200, {});
        }
      } catch(e) { json(res, 200, {}); }
      return;
    }

    if (pathname === '/api/mappings' && req.method === 'POST') {
      const body = await readBody(req);
      fs.writeFileSync(MAPPING_FILE, body);
      console.log('💾 Account mappings saved.');
      json(res, 200, { success: true });
      return;
    }

    // GET history
    if (pathname === '/api/history' && req.method === 'GET') {
      try {
        if (fs.existsSync(HISTORY_FILE)) {
          const data = fs.readFileSync(HISTORY_FILE, 'utf8');
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(data);
        } else {
          json(res, 200, []);
        }
      } catch(e) { json(res, 200, []); }
      return;
    }

    // POST — append one record to history
    if (pathname === '/api/history' && req.method === 'POST') {
      const record = JSON.parse(await readBody(req));
      let history = [];
      try {
        if (fs.existsSync(HISTORY_FILE))
          history = JSON.parse(fs.readFileSync(HISTORY_FILE, 'utf8'));
      } catch(e) {}
      history.push(record);
      fs.writeFileSync(HISTORY_FILE, JSON.stringify(history, null, 2));
      console.log(`📝 History recorded: ${record.payoutDate} — ${record.status}`);
      json(res, 200, { success: true });
      return;
    }

    // DELETE — clear all history
    if (pathname === '/api/history' && req.method === 'DELETE') {
      if (fs.existsSync(HISTORY_FILE)) fs.unlinkSync(HISTORY_FILE);
      console.log('🗑 Post history cleared.');
      json(res, 200, { success: true });
      return;
    }

    res.writeHead(404); res.end('Not found');

  } catch (err) {
    console.error('API error:', err.message);
    json(res, 500, { error: err.message });
  }
});

// ── OAuth Helpers ──
function buildAuthUrl() {
  const params = new URLSearchParams({
    client_id:     state.clientId,
    response_type: 'code',
    scope:         SCOPES,
    redirect_uri:  getRedirectUri(),
    state:         state.oauthState,
  });
  return `https://appcenter.intuit.com/connect/oauth2?${params.toString()}`;
}

async function exchangeCode(code) {
  const basic    = Buffer.from(`${state.clientId}:${state.clientSecret}`).toString('base64');
  const postData = `grant_type=authorization_code&code=${encodeURIComponent(code)}&redirect_uri=${encodeURIComponent(getRedirectUri())}`;
  const data = await httpsReq({
    host:   'oauth.platform.intuit.com',
    path:   '/oauth2/v1/tokens/bearer',
    method: 'POST',
    headers: {
      'Authorization':  `Basic ${basic}`,
      'Content-Type':   'application/x-www-form-urlencoded',
      'Accept':         'application/json',
      'Content-Length': Buffer.byteLength(postData),
    },
  }, postData);
  if (data.error) throw new Error(`${data.error_description || data.error} (${data.error})`);
  return data;
}

// ── Token Management ──
async function refreshAccessToken() {
  console.log('🔄 Auto-refreshing access token…');
  const basic    = Buffer.from(`${state.clientId}:${state.clientSecret}`).toString('base64');
  const postData = `grant_type=refresh_token&refresh_token=${encodeURIComponent(state.refreshToken)}`;
  const data = await httpsReq({
    host:   'oauth.platform.intuit.com',
    path:   '/oauth2/v1/tokens/bearer',
    method: 'POST',
    headers: {
      'Authorization':  `Basic ${basic}`,
      'Content-Type':   'application/x-www-form-urlencoded',
      'Accept':         'application/json',
      'Content-Length': Buffer.byteLength(postData),
    },
  }, postData);
  if (data.error) throw new Error(`Token refresh failed: ${data.error_description || data.error}`);
  state.accessToken  = data.access_token;
  if (data.refresh_token) state.refreshToken = data.refresh_token;
  state.tokenExpiry  = Date.now() + ((data.expires_in || 3600) - 60) * 1000;
  saveTokens();
  console.log('✅ Token refreshed. Expires in', Math.round((state.tokenExpiry - Date.now()) / 60000), 'min');
}

async function ensureToken() {
  if (!state.connected || !state.refreshToken) throw new Error('Not connected to QuickBooks. Please connect via the dashboard.');
  if (Date.now() >= state.tokenExpiry) await refreshAccessToken();
}

// ── QBO Requests ──
function qboGet(p) {
  return httpsReq({
    host:    QBO_HOST[state.environment] || QBO_HOST.production,
    path:    p,
    method:  'GET',
    headers: { 'Authorization': `Bearer ${state.accessToken}`, 'Accept': 'application/json' },
  });
}

function qboPost(p, body) {
  return httpsReq({
    host:    QBO_HOST[state.environment] || QBO_HOST.production,
    path:    p,
    method:  'POST',
    headers: {
      'Authorization':  `Bearer ${state.accessToken}`,
      'Content-Type':   'application/json',
      'Accept':         'application/json',
      'Content-Length': Buffer.byteLength(body),
    },
  }, body);
}

// ── Callback Page (shown in popup after Intuit redirects) ──
function callbackPage(status, message) {
  const isSuccess = status === 'success';
  return `<!DOCTYPE html><html><head><meta charset="UTF-8">
  <style>
    body{font-family:Inter,sans-serif;background:#080c14;color:#e2eaf8;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;}
    .box{text-align:center;padding:40px;background:#141c2b;border-radius:16px;border:1px solid ${isSuccess?'#22c55e':'#ef4444'};max-width:420px;}
    .icon{font-size:52px;margin-bottom:16px;}
    h2{font-size:20px;margin-bottom:10px;color:${isSuccess?'#22c55e':'#ef4444'};}
    p{color:#7a91b4;font-size:14px;line-height:1.6;}
  </style></head><body>
  <div class="box">
    <div class="icon">${isSuccess?'✅':'❌'}</div>
    <h2>${isSuccess?'Connected to QuickBooks!':'Connection Failed'}</h2>
    <p>${message}</p>
    ${isSuccess?'<p style="margin-top:16px;color:#4ade80">This window will close automatically…</p>':'<p style="margin-top:16px">Please close this window and try again.</p>'}
  </div>
  ${isSuccess?'<script>setTimeout(()=>window.close(),2000)</script>':''}
  </body></html>`;
}

// ── Utilities ──
function httpsReq(options, body) {
  return new Promise((resolve, reject) => {
    const req = https.request(options, (r) => {
      let d = '';
      r.on('data', c => d += c);
      r.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve(d); } });
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let b = '';
    req.on('data', c => b += c);
    req.on('end', () => resolve(b));
    req.on('error', reject);
  });
}

function json(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function setCors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}

// ── Start ──
loadTokens();
server.listen(PORT, () => {
  console.log('');
  console.log('  ██╗  ██╗██╗██████╗ ███████╗████████╗██████╗  ██████╗ ███╗   ██╗ ██████╗ ');
  console.log('  ██║ ██╔╝██║██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██╔═══██╗████╗  ██║██╔════╝ ');
  console.log('  █████╔╝ ██║██║  ██║███████╗   ██║   ██████╔╝██║   ██║██╔██╗ ██║██║  ███╗');
  console.log('  ██╔═██╗ ██║██║  ██║╚════██║   ██║   ██╔══██╗██║   ██║██║╚██╗██║██║   ██║');
  console.log('  ██║  ██╗██║██████╔╝███████║   ██║   ██║  ██║╚██████╔╝██║ ╚████║╚██████╔╝');
  console.log('  ╚═╝  ╚═╝╚═╝╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ ');
  console.log('');
  console.log(`  QBO Journal Entry Server  →  http://localhost:${PORT}`);
  if (state.connected) {
    console.log(`  Status: ✅ Already connected (Realm: ${state.realmId})`);
  } else {
    console.log('  Status: Not connected — open dashboard to connect');
  }
  console.log('');
});
