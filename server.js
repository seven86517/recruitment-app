/**
 * 房懂懂招聘系统 — 飞书 API 代理服务器
 * 零依赖，仅使用 Node.js 内置模块
 * 
 * 职责：
 * 1. 提供静态文件服务（HTML/CSS/JS）
 * 2. 代理 /api/feishu/* → https://open.feishu.cn/open-apis/*
 * 3. 管理 tenant_access_token（服务端缓存，浏览器不可见）
 * 4. 接收前端配置并安全存储 App ID / App Secret
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const url = require('url');
const crypto = require('crypto');

// ===== 配置 =====
const PORT = parseInt(process.env.PORT || '3001', 10);
const STATIC_DIR = __dirname;
const FEISHU_API_HOST = 'open.feishu.cn';
const FEISHU_TIMEOUT = parseInt(process.env.FEISHU_TIMEOUT || '15000', 10);

// ===== 服务端凭证存储（不暴露给浏览器） =====
const CREDENTIALS_FILE = path.join(__dirname, '.credentials.json');

function loadCredentials() {
  try {
    if (fs.existsSync(CREDENTIALS_FILE)) {
      var saved = JSON.parse(fs.readFileSync(CREDENTIALS_FILE, 'utf-8'));
      return saved;
    }
  } catch(e) {}
  return {};
}

function saveCredentials() {
  try {
    fs.writeFileSync(CREDENTIALS_FILE, JSON.stringify({ appId: appId, appSecret: appSecret }, null, 2), 'utf-8');
  } catch(e) {
    console.error('[WARN] Failed to save credentials:', e.message);
  }
}

// 启动时从文件加载凭证
var _saved = loadCredentials();
let appId = process.env.FEISHU_APP_ID || _saved.appId || '';
let appSecret = process.env.FEISHU_APP_SECRET || _saved.appSecret || '';
if (appId) console.log('[INFO] Credentials loaded from .credentials.json (appId: ' + appId.slice(0, 8) + '...)');

let tenantToken = null;
let tokenExpiresAt = 0;

// 用户个人令牌（PAT）—— 绕过应用权限限制，直接用用户身份访问
let userAccessToken = '';

// ===== MIME 类型映射 =====
const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.htm':  'text/html; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  '.mjs':  'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png':  'image/png',
  '.jpg':  'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif':  'image/gif',
  '.svg':  'image/svg+xml',
  '.ico':  'image/x-icon',
  '.webp': 'image/webp',
  '.woff': 'font/woff',
  '.woff2':'font/woff2',
  '.ttf':  'font/ttf',
  '.txt':  'text/plain; charset=utf-8',
  '.xml':  'application/xml; charset=utf-8',
  '.pdf':  'application/pdf'
};

// ===== 工具函数 =====
function jsonResponse(res, statusCode, data) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
  });
  res.end(JSON.stringify(data, null, 2));
}

function readRequestBody(req) {
  return new Promise(function(resolve) {
    var chunks = [];
    req.on('data', function(c) { chunks.push(c); });
    req.on('end', function() {
      var raw = Buffer.concat(chunks).toString('utf-8');
      try { resolve(JSON.parse(raw)); }
      catch(e) { resolve(raw); }
    });
  });
}

function log(level, msg) {
  var ts = new Date().toISOString().slice(0, 19).replace('T', ' ');
  console.log('[' + ts + '] [' + level + '] ' + msg);
}

// ===== Tenant Access Token 管理 =====
function fetchTenantToken() {
  return new Promise(function(resolve, reject) {
    // 缓存有效则直接返回
    if (tenantToken && Date.now() < tokenExpiresAt) {
      return resolve(tenantToken);
    }
    if (!appId || !appSecret) {
      return reject(new Error('NO_CREDENTIALS'));
    }

    var body = JSON.stringify({ app_id: appId, app_secret: appSecret });
    var options = {
      hostname: FEISHU_API_HOST,
      path: '/open-apis/auth/v3/tenant_access_token/internal',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Length': Buffer.byteLength(body)
      },
      timeout: FEISHU_TIMEOUT
    };

    var req = https.request(options, function(resp) {
      var data = '';
      resp.on('data', function(c) { data += c; });
      resp.on('end', function() {
        try {
          var json = JSON.parse(data);
          if (json.code === 0 && json.tenant_access_token) {
            tenantToken = json.tenant_access_token;
            // 提前 300 秒过期，防止边界问题
            tokenExpiresAt = Date.now() + (json.expire - 300) * 1000;
            log('INFO', 'Tenant token refreshed, expires in ' + json.expire + 's');
            resolve(tenantToken);
          } else {
            log('ERROR', 'Token fetch failed: ' + data);
            reject(new Error('TOKEN_FAILED: ' + (json.msg || json.code)));
          }
        } catch(e) { reject(e); }
      });
    });
    req.on('error', function(e) { reject(e); });
    req.on('timeout', function() { req.destroy(); reject(new Error('TIMEOUT')); });
    req.write(body);
    req.end();
  });
}

// ===== 飞书 API 代理 =====
function getEffectiveToken() {
  return new Promise(function(resolve, reject) {
    // 优先使用用户个人令牌（PAT），绕过应用权限问题
    if (userAccessToken) {
      return resolve({ token: userAccessToken, type: 'user' });
    }
    // 回退到 tenant_access_token
    fetchTenantToken().then(function(token) {
      resolve({ token: token, type: 'tenant' });
    }).catch(reject);
  });
}

function proxyFeishu(req, res, feishuPath) {
  getEffectiveToken().then(function(result) {
    var token = result.token;
    var options = {
      hostname: FEISHU_API_HOST,
      path: '/open-apis' + feishuPath,
      method: req.method,
      headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json; charset=utf-8'
      },
      timeout: FEISHU_TIMEOUT
    };

    var proxyReq = https.request(options, function(proxyRes) {
      var data = '';
      proxyRes.on('data', function(c) { data += c; });
      proxyRes.on('end', function() {
        res.writeHead(proxyRes.statusCode, {
          'Content-Type': 'application/json; charset=utf-8',
          'Access-Control-Allow-Origin': '*'
        });
        res.end(data);
        log('INFO', 'Proxy ' + req.method + ' ' + feishuPath + ' → ' + proxyRes.statusCode);
      });
    });

    proxyReq.on('error', function(e) {
      log('ERROR', 'Proxy error for ' + feishuPath + ': ' + e.message);
      jsonResponse(res, 502, { code: -1, msg: '飞书 API 代理错误: ' + e.message });
    });

    proxyReq.on('timeout', function() {
      proxyReq.destroy();
      jsonResponse(res, 504, { code: -1, msg: '飞书 API 请求超时' });
    });

    if (req.body && typeof req.body === 'string') {
      proxyReq.write(req.body);
    }
    proxyReq.end();
  }).catch(function(err) {
    if (err.message === 'NO_CREDENTIALS') {
      jsonResponse(res, 401, { code: -1, msg: '未配置飞书 API 凭证，请在设置中配置 App ID 和 App Secret' });
    } else {
      log('ERROR', 'Token error: ' + err.message);
      jsonResponse(res, 500, { code: -1, msg: '飞书认证失败: ' + err.message });
    }
  });
}

// ===== 静态文件服务 =====
// 预计算静态目录的规范化基准路径
var STATIC_DIR_FULL = path.resolve(STATIC_DIR);
var STATIC_BASE = STATIC_DIR_FULL.replace(/\\/g, '/').toLowerCase();

function serveStatic(req, res, filePath) {
  // 安全检查：防止目录穿越
  // 使用 path.join 避免 Windows 上 /xxx 被 path.resolve 当作绝对路径
  var joined = path.join(STATIC_DIR, filePath);
  var resolved = path.resolve(joined).replace(/\\/g, '/');
  var lowerResolved = resolved.toLowerCase();
  if (lowerResolved.indexOf(STATIC_BASE) !== 0) {
    console.log('[WARN] Path traversal blocked: ' + resolved + ' vs ' + STATIC_BASE);
    res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('403 Forbidden');
    return;
  }

  var ext = path.extname(resolved).toLowerCase();
  var contentType = MIME_TYPES[ext] || 'application/octet-stream';

  fs.readFile(resolved, function(err, data) {
    if (err) {
      if (err.code === 'ENOENT') {
        // 404 → 返回 index.html (SPA 路由回退)
        fs.readFile(path.join(STATIC_DIR, 'index.html'), function(err2, fallback) {
          if (err2) {
            res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
            res.end('404 Not Found');
            return;
          }
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
          res.end(fallback);
        });
        return;
      }
      res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('500 Internal Server Error');
      return;
    }
    res.writeHead(200, {
      'Content-Type': contentType,
      'Cache-Control': ext.match(/\.(png|jpg|jpeg|gif|svg|ico|webp|woff2?|ttf)$/) 
        ? 'public, max-age=86400' 
        : 'no-cache'
    });
    res.end(data);
  });
}

// ===== OAuth 2.0 用户授权 =====
var oauthStates = {}; // state -> { expires }

// GET /api/oauth/login — 重定向到飞书授权页
// GET /api/oauth/callback — 飞书回调，交换 token

function handleOAuthCallback(req, res, query) {
  var code = query.code;
  var state = query.state;
  
  if (!code) {
    res.writeHead(302, { 'Location': '/?error=no_code' });
    res.end();
    return;
  }
  
  // 用 code 交换 user_access_token
  var appAccessToken = tenantToken; // use cached tenant token as app token
  
  function exchangeToken(token) {
    var body = JSON.stringify({
      grant_type: 'authorization_code',
      code: code
    });
    var options = {
      hostname: FEISHU_API_HOST,
      path: '/open-apis/authen/v1/access_token',
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Length': Buffer.byteLength(body)
      },
      timeout: FEISHU_TIMEOUT
    };
    
    var apiReq = https.request(options, function(resp) {
      var data = '';
      resp.on('data', function(c) { data += c; });
      resp.on('end', function() {
        try {
          var json = JSON.parse(data);
          if (json.access_token) {
            userAccessToken = json.access_token;
            log('INFO', 'User access token obtained, expires in ' + json.expires_in + 's');
            // 重定向到首页，带上成功标记
            res.writeHead(302, { 'Location': '/?auth=success' });
            res.end();
          } else {
            log('ERROR', 'Token exchange failed: ' + data);
            res.writeHead(302, { 'Location': '/?auth=failed&error=' + encodeURIComponent(json.msg || 'unknown') });
            res.end();
          }
        } catch(e) {
          log('ERROR', 'Token exchange parse error: ' + e.message);
          res.writeHead(302, { 'Location': '/?auth=failed&error=parse' });
          res.end();
        }
      });
    });
    apiReq.on('error', function(e) {
      log('ERROR', 'OAuth exchange error: ' + e.message);
      res.writeHead(302, { 'Location': '/?auth=failed&error=network' });
      res.end();
    });
    apiReq.write(body);
    apiReq.end();
  }
  
  // 先确保有 app token
  if (appId && appSecret) {
    fetchTenantToken().then(function(token) {
      exchangeToken(token);
    }).catch(function(err) {
      log('ERROR', 'Failed to get app token for OAuth: ' + err.message);
      res.writeHead(302, { 'Location': '/?auth=failed&error=no_app_token' });
      res.end();
    });
  } else {
    res.writeHead(302, { 'Location': '/?auth=failed&error=no_credentials' });
    res.end();
  }
}

// ===== 主请求路由 =====
var server = http.createServer(function(req, res) {
  var parsed = url.parse(req.url, true);
  var pathname = parsed.pathname;

  // CORS 预检请求
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400'
    });
    res.end();
    return;
  }

  // ===== API 路由 =====

  // POST /api/config — 保存飞书凭证（服务端存储）
  if (pathname === '/api/config' && req.method === 'POST') {
    readRequestBody(req).then(function(body) {
      appId = (body && body.appId) || appId || '';
      appSecret = (body && body.appSecret) || appSecret || '';
      if (body && body.userToken !== undefined) {
        userAccessToken = body.userToken || '';
      }
      tenantToken = null;
      tokenExpiresAt = 0;
      // 持久化凭证到文件，下次重启自动加载
      saveCredentials();
      log('INFO', 'Credentials updated (appId: ' + (appId ? appId.slice(0, 8) + '...' : 'empty') + ', userToken: ' + (userAccessToken ? 'set' : 'not set') + ')');
      jsonResponse(res, 200, { success: true, userTokenSet: !!userAccessToken });
    }).catch(function(e) {
      jsonResponse(res, 400, { error: 'Invalid request body' });
    });
    return;
  }

  // GET /api/status — 检查连接状态
  if (pathname === '/api/status') {
    var ready = !!userAccessToken;
    if (!ready && (!appId || !appSecret)) {
      jsonResponse(res, 200, { ready: false, reason: 'no_credentials' });
      return;
    }
    if (!ready) {
      fetchTenantToken().then(function() {
        jsonResponse(res, 200, { ready: true, mode: 'tenant' });
      }).catch(function(e) {
        jsonResponse(res, 200, { ready: false, reason: e.message });
      });
      return;
    }
    jsonResponse(res, 200, { ready: true, mode: 'user' });
    return;
  }

  // GET /api/oauth/login — 跳转飞书授权页
  if (pathname === '/api/oauth/login') {
    if (!appId) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end('<h2>请先在设置中配置 App ID</h2>');
      return;
    }
    var redirectUri = 'http://localhost:' + PORT + '/api/oauth/callback';
    var state = crypto.randomBytes(8).toString('hex');
    oauthStates[state] = { expires: Date.now() + 600000 }; // 10分钟有效
    var authUrl = 'https://open.feishu.cn/open-apis/authen/v1/authorize' +
      '?app_id=' + encodeURIComponent(appId) +
      '&redirect_uri=' + encodeURIComponent(redirectUri) +
      '&state=' + state +
      '&scope=';
    res.writeHead(302, { 'Location': authUrl });
    res.end();
    return;
  }

  // GET /api/oauth/callback — 飞书 OAuth 回调
  if (pathname === '/api/oauth/callback') {
    handleOAuthCallback(req, res, parsed.query);
    return;
  }

  // /api/feishu/* — 飞书 API 代理（通配）
  if (pathname.startsWith('/api/feishu/')) {
    var feishuPath = pathname.replace('/api/feishu', '');
    if (parsed.search) feishuPath += parsed.search;
    
    // POST/PUT/PATCH 需要读取 body
    if (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH') {
      readRequestBody(req).then(function(body) {
        req.body = typeof body === 'string' ? body : JSON.stringify(body);
        proxyFeishu(req, res, feishuPath);
      });
      return;
    }
    proxyFeishu(req, res, feishuPath);
    return;
  }

  // ===== 静态文件服务 =====
  var filePath = pathname === '/' ? '/index.html' : pathname;
  serveStatic(req, res, filePath);
});

// ===== 启动 =====
server.listen(PORT, function() {
  log('INFO', '========================================');
  log('INFO', '  房懂懂招聘系统 — 代理服务器已启动');
  log('INFO', '  端口: ' + PORT);
  log('INFO', '  静态目录: ' + STATIC_DIR);
  log('INFO', '  飞书 API: /api/feishu/* → ' + FEISHU_API_HOST);
  log('INFO', '  凭证状态: ' + (appId ? '已配置' : '未配置，请在设置中填写'));
  log('INFO', '========================================');
});

// 优雅退出
process.on('SIGTERM', function() {
  log('INFO', 'Received SIGTERM, shutting down...');
  server.close();
  process.exit(0);
});

process.on('SIGINT', function() {
  log('INFO', 'Received SIGINT, shutting down...');
  server.close();
  process.exit(0);
});
