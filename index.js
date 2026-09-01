require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(express.json());

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const PORT = process.env.PORT || 3000;

// Very small in-memory rate limiter per (username) to slow down brute force.
// For real production use, put this behind a proper rate limiter / WAF.
const failedAttempts = new Map(); // username -> { count, lockUntil }
const MAX_ATTEMPTS = 5;
const LOCK_MS = 5 * 60 * 1000; // 5 minutes

function isLocked(username) {
  const entry = failedAttempts.get(username);
  if (!entry) return false;
  if (entry.lockUntil && Date.now() < entry.lockUntil) return true;
  if (entry.lockUntil && Date.now() >= entry.lockUntil) {
    failedAttempts.delete(username);
  }
  return false;
}

function recordFailure(username) {
  const entry = failedAttempts.get(username) || { count: 0, lockUntil: null };
  entry.count += 1;
  if (entry.count >= MAX_ATTEMPTS) {
    entry.lockUntil = Date.now() + LOCK_MS;
    entry.count = 0;
  }
  failedAttempts.set(username, entry);
}

function clearFailures(username) {
  failedAttempts.delete(username);
}

// POST /api/register
// Not called by the Rust client, but you need some way to create accounts.
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res
      .status(400)
      .json({ success: false, message: 'username and password are required' });
  }
  if (password.length < 8) {
    return res
      .status(400)
      .json({ success: false, message: 'password must be at least 8 characters' });
  }

  const { data: existing, error: lookupErr } = await supabase
    .from('users')
    .select('id')
    .eq('username', username)
    .maybeSingle();

  if (lookupErr) {
    return res.status(500).json({ success: false, message: 'database error' });
  }
  if (existing) {
    return res.status(409).json({ success: false, message: 'username already taken' });
  }

  const password_hash = await bcrypt.hash(password, 12);

  const { error: insertErr } = await supabase
    .from('users')
    .insert({ username, password_hash, hwid: null });

  if (insertErr) {
    return res.status(500).json({ success: false, message: 'could not create account' });
  }

  return res.json({ success: true, message: 'account created' });
});

// POST /api/login
// Body: { username, password, hwid } -> matches LoginRequest in the Rust client.
// Response: { success, message } -> matches LoginResponse in the Rust client.
app.post('/api/login', async (req, res) => {
  const { username, password, hwid } = req.body || {};

  if (!username || !password || !hwid) {
    return res.json({
      success: false,
      message: 'username, password, and hwid are required',
    });
  }

  if (isLocked(username)) {
    return res.json({
      success: false,
      message: 'too many failed attempts, try again later',
    });
  }

  const { data: user, error } = await supabase
    .from('users')
    .select('id, password_hash, hwid')
    .eq('username', username)
    .maybeSingle();

  if (error) {
    return res.json({ success: false, message: 'database error, try again later' });
  }
  if (!user) {
    recordFailure(username);
    return res.json({ success: false, message: 'invalid username or password' });
  }

  const passwordOk = await bcrypt.compare(password, user.password_hash);
  if (!passwordOk) {
    recordFailure(username);
    return res.json({ success: false, message: 'invalid username or password' });
  }

  // No hwid bound yet -> bind this device on first successful login.
  if (!user.hwid) {
    const { error: bindErr } = await supabase
      .from('users')
      .update({ hwid })
      .eq('id', user.id);

    if (bindErr) {
      return res.json({ success: false, message: 'could not bind device, try again' });
    }

    clearFailures(username);
    return res.json({ success: true, message: 'login successful (device bound)' });
  }

  // hwid already bound -> must match this device.
  if (user.hwid !== hwid) {
    recordFailure(username);
    return res.json({
      success: false,
      message: 'this account is already bound to a different device',
    });
  }

  clearFailures(username);
  return res.json({ success: true, message: 'login successful' });
});

app.get('/health', (_req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`Auth server listening on port ${PORT}`);
});
