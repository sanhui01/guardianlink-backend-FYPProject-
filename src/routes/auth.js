// src/routes/auth.js
import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import speakeasy from 'speakeasy';
import qrcode from 'qrcode';
import bcrypt from 'bcrypt';
import mongoose from 'mongoose';

import User from '../models/User.js';
import {
  signAuthToken, signRefreshToken,
  verifyAuthToken, verifyRefreshToken
} from '../utils/jwt.js';
import { sendResetCode, sendVerifyCode } from '../utils/mailer.js';
import { schemas, validate } from '../middleware/validators.js';
import { loginLimiter, forgotLimiter } from '../middleware/rateLimiters.js';
import { requireAuth } from '../middleware/authz.js';
import { recordSecurityEventAndNotify } from '../utils/securityEvents.js';

const router = Router();
const limiter = rateLimit({ windowMs: 60_000, max: 20, standardHeaders: true, legacyHeaders: false });
router.use(limiter);

const ACCESS_SECRET = process.env.JWT_SECRET || 'dev-secret';
const RESET_TTL_MIN = Number(process.env.RESET_CODE_TTL_MIN || 10);
const MAX_RESET_ATTEMPTS  = 6;

// NEW: login attempt / lock constants
const ATTEMPT_DELAY_THRESHOLD = 3; // show retryAfter after 3 wrong attempts
const LOCK_THRESHOLD = 7;          // lock after 7 wrong attempts
const LOCK_MINUTES = 15;           // 15-minute lock

const LATE_HOUR_START = 1; // 1am
const LATE_HOUR_END   = 5; // 5am

const bearer = (req) => {
  const h = req.headers.authorization || '';
  return h.startsWith('Bearer ') ? h.slice(7) : null;
};
const signMfaTempToken = (user) =>
  jwt.sign({ sub: user._id.toString(), email: user.email, mfa: true }, ACCESS_SECRET, { expiresIn: '5m' });

// Simple password policy: min 10 chars + at least 2 categories
function meetsPasswordPolicy(pw = "") {
  if (typeof pw !== "string") return false;
  const trimmed = pw.trim();
  if (trimmed.length < 10) return false;

  const hasUpper = /[A-Z]/.test(trimmed);
  const hasLower = /[a-z]/.test(trimmed);
  const hasDigit = /[0-9]/.test(trimmed);
  const hasSymbol = /[^A-Za-z0-9]/.test(trimmed);

  const categories = [hasUpper, hasLower, hasDigit, hasSymbol].filter(Boolean).length;
  return categories >= 2;
}

async function attachDeviceSessionOrBlock({
  user,
  deviceId,
  deviceName,
  platform,
  ip,
  now,
  req,
  res,
}) {
  if (!deviceId) {
    // If app didn't send a deviceId, don't enforce (can tighten later)
    return { allowed: true };
  }

  // Ensure deviceIds array exists and track this deviceId
  user.deviceIds = user.deviceIds || [];
  if (!user.deviceIds.includes(deviceId)) {
    user.deviceIds.push(deviceId);
  }

  // Ensure sessions array exists
  user.sessions = user.sessions || [];

  const maxDevices =
    (user.deviceLimits?.maxDevices) || (user.role === 'Child' ? 2 : 3);

  // Check if this device already has a session
  let session = user.sessions.find((s) => s.deviceId === deviceId);

  if (!session) {
    // --- NEW DEVICE ---
    if (user.sessions.length >= maxDevices) {
      // 1) Log security event + notify parent
      await recordSecurityEventAndNotify({
        user,
        type: 'new_device',
        severity: 'medium',
        message: `Login from NEW device was BLOCKED (device limit = ${maxDevices}).`,
        details: {
          deviceId,
          deviceName: deviceName || null,
          platform: platform || 'android',
          ip,
          maxDevices,
          currentDevices: user.sessions.map((s) => s.deviceId),
        },
      });

      // 2) Block login (NO tokens)
      res.status(403).json({
        message:
          'Device limit reached. Remove an old device from Security & Devices before logging in on a new device.',
      });

      return { allowed: false };
    }

    // Under limit → allow and add session
    session = {
      deviceId,
      deviceName: deviceName || null,
      platform: platform || 'android',
      firstSeenAt: now,
      lastSeenAt: now,
      lastIp: ip || null,
    };
    user.sessions.push(session);

    // New device allowed → keep your existing style of event
    await recordSecurityEventAndNotify({
      user,
      type: 'new_device',
      severity: 'medium',
      message: `${user.role === 'Child' ? 'Child' : 'User'} ${user.email} signed in from a new device.`,
      details: {
        deviceId,
        deviceName: deviceName || null,
        platform: platform || 'android',
        ip,
      },
    });
  } else {
    // --- EXISTING DEVICE ---
    session.lastSeenAt = now;
    session.lastIp = ip || null;
    if (deviceName) session.deviceName = deviceName;
    if (platform) session.platform = platform;
  }

  return { allowed: true };
}

/* -------- /auth/me -------- */
router.get('/me', async (req, res) => {
  try {
    const token = bearer(req);
    if (!token) return res.status(401).json({ message: 'No token' });
    const payload = verifyAuthToken(token);
    const user = await User.findById(payload.sub)
      .select('email role isSuperuser tokenVersion displayName emailVerified mfa twoFA');
    if (!user) return res.status(404).json({ message: 'User not found' });
    if ((payload.tv ?? 0) !== (user.tokenVersion ?? 0)) {
      return res.status(401).json({ message: 'Session expired' });
    }
    res.json({ user: {
      id: user._id, email: user.email, role: user.role,
      isSuperuser: user.isSuperuser, displayName: user.displayName ?? '',
      emailVerified: !!user.emailVerified,
      mfaEnabled: !!(user.twoFA?.enabled || user.mfa?.enabled)
    }});
  } catch { res.status(401).json({ message: 'Invalid token' }); }
});

router.patch('/me', requireAuth, async (req, res) => {
  const { displayName } = req.body || {};
  const me = await User.findById(req.user._id || req.user.id); 
  if (!me) return res.status(404).json({ message: 'User not found' });

  if (typeof displayName === 'string') {
    const dn = displayName.trim();
    if (!dn) return res.status(400).json({ message: 'Display name required' });
    if (dn.length > 40) return res.status(400).json({ message: 'Max 40 chars' });
    me.displayName = dn;
    await me.save();
  }

  res.json({ ok: true, user: { id: me.id, displayName: me.displayName } });
});

/* -------- Parent-only legacy create child (kept) -------- */
router.post('/children', requireAuth, async (req, res) => {
  try {
    if (req.user.role !== 'Parent') return res.status(403).json({ message: 'Parents only' });
    const { email, password, displayName } = req.body || {};
    if (!email || !password) return res.status(400).json({ message: 'email and password required' });

    const emailNorm = email.trim().toLowerCase();
    if (await User.findOne({ email: emailNorm })) return res.status(409).json({ message: 'Email already exists' });

    const child = await User.create({
      email: emailNorm,
      passwordHash: await bcrypt.hash(password, 12),
      role: 'Child',
      familyId: req.user.familyId,     // ensure same household
      parentId: req.user._id,
      displayName: (displayName || '').trim() || null,
      // child default device limit = 2
      deviceLimits: { maxDevices: 2 }
    });
    res.status(201).json({ user: { id: child._id, email: child.email, role: child.role, displayName: child.displayName, parentId: req.user._id }});
  } catch (e) { console.error('auth/children error:', e); res.status(500).json({ message: 'Failed to create child' }); }
});

/* -------- /auth/register (Parent only) -------- */
router.post('/register', validate(schemas.register), async (req, res) => {
  try {
    const { email, password, deviceId, deviceName, platform, displayName } = req.body;
    const emailNorm = email.trim().toLowerCase();
    if (await User.findOne({ email: emailNorm })) return res.status(409).json({ message: 'Account already exists' });

    // Password constraints (Option B)
    if (!meetsPasswordPolicy(password)) {
      return res.status(400).json({
        message: 'Weak password. Min 10 chars and at least 2 of: uppercase, lowercase, number, symbol.'
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const nameSafe = (displayName && displayName.toString().trim()) || emailNorm.split('@')[0];
    const familyId = new mongoose.Types.ObjectId();

    const isSuperuser = true;
  
    const user = await User.create({
      email: emailNorm,
      passwordHash,
      role: 'Parent',
      isSuperuser,
      familyId,
      displayName: nameSafe,
      deviceIds: deviceId ? [deviceId] : [],
      sessions: deviceId ? [{
        deviceId,
        deviceName: deviceName || null,
        platform: platform || 'android'
      }] : [],
      deviceLimits: { maxDevices: 3 } // parent default limit
    });

    const graceMs = 48 * 60 * 60 * 1000;   // 48 hours
    user.verify = { expires: new Date(Date.now() + graceMs) };  
    await user.save();

    const token   = signAuthToken(user);
    const refresh = signRefreshToken(user);
    res.status(201).json({
      token, accessToken: token, refreshToken: refresh,
      user: { id: user._id, email: user.email, role: user.role, isSuperuser: user.isSuperuser, displayName: user.displayName }
    });
  } catch (e) { console.error('register error:', e); res.status(500).json({ message: 'Server error' }); }
});

/* -------- /auth/login -------- */
router.post('/login', loginLimiter, validate(schemas.login), async (req, res) => {
  try {
    const { email, password, deviceId, deviceName, platform } = req.body;
    const emailNorm = email.trim().toLowerCase();
    const user = await User.findOne({ email: emailNorm });
    const now = new Date();

    if (!user) {
      // no user -> generic message (avoid user enumeration)
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Check if account is locked
    if (user.loginSecurity?.lockedUntil && user.loginSecurity.lockedUntil > now) {
      const remainingMs = user.loginSecurity.lockedUntil.getTime() - now.getTime();
      const remainingSec = Math.max(5, Math.round(remainingMs / 1000));
      return res.status(423).json({
        message: 'Account temporarily locked due to too many attempts',
        retryAfter: remainingSec,
        locked: true
      });
    }

    // Compare password
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      // Increment attempt counter
      user.loginSecurity = user.loginSecurity || {};
      user.loginSecurity.attempts = (user.loginSecurity.attempts || 0) + 1;

      const attempts = user.loginSecurity.attempts;

      // Lock threshold
      if (attempts >= LOCK_THRESHOLD) {
        // apply lock if not already locked
        if (!user.loginSecurity.lockedUntil || user.loginSecurity.lockedUntil <= now) {
          user.loginSecurity.lockedUntil = new Date(now.getTime() + LOCK_MINUTES * 60 * 1000);

          // Only send lock alert once per lock window
          const lastLockAt = user.loginSecurity.lastLockAlertAt;
          const recentlyAlerted = lastLockAt && (now.getTime() - lastLockAt.getTime()) < (LOCK_MINUTES * 60 * 1000);
          if (!recentlyAlerted) {
            user.loginSecurity.lastLockAlertAt = now;
            await user.save();

            await recordSecurityEventAndNotify({
              user,
              type: 'login_lock',
              severity: 'high',
              message: `Too many failed login attempts for ${user.email}. Account has been locked for ${LOCK_MINUTES} minutes.`,
              details: { attempts, lockMinutes: LOCK_MINUTES }
            });
          } else {
            await user.save();
          }
        } else {
          await user.save();
        }

        return res.status(423).json({
          message: 'Account temporarily locked due to too many attempts',
          locked: true
        });
      }

      // Below lock threshold: soft warning + optional alert
if (attempts >= ATTEMPT_DELAY_THRESHOLD) {
  // Avoid spamming alerts: only once every 10 minutes
  user.loginSecurity = user.loginSecurity || {};
  const lastSoft = user.loginSecurity.lastSoftAlertAt;
  const recentlyAlerted =
    lastSoft && (now.getTime() - lastSoft.getTime()) < 10 * 60 * 1000; // 10 min

  if (!recentlyAlerted) {
    user.loginSecurity.lastSoftAlertAt = now;

    await recordSecurityEventAndNotify({
      user,
      type: 'login_bruteforce',
      severity: 'medium',
      message: `Multiple failed login attempts detected for ${user.email}.`,
      details: { attempts }
    });
  }

  await user.save();

  return res.status(429).json({
    message: 'Too many failed attempts. Please wait a moment before trying again.',
    retryAfter: 15
  });
}

      await user.save();
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Successful login: reset attempts & lock
    if (user.loginSecurity) {
      user.loginSecurity.attempts = 0;
      user.loginSecurity.lockedUntil = null;
      // we do not reset lastLockAlertAt so we can see last lock timing
    }

        const ip = (req.ip || req.connection?.remoteAddress || '').toString();

    const { allowed } = await attachDeviceSessionOrBlock({
      user,
      deviceId,
      deviceName,
      platform,
      ip,
      now,
      req,
      res,
    });

    if (!allowed) {
      // helper already sent 403 response + JSON
      return;
    }


    // Late-night login detection for child accounts
    if (user.role === 'Child') {
      const hour = now.getHours();
      if (hour >= LATE_HOUR_START && hour < LATE_HOUR_END) {
        // check last late_login event to avoid spam
        const SecurityEvent = (await import('../models/SecurityEvent.js')).default;
        const last = await SecurityEvent.findOne({
          userId: user._id,
          type: 'late_login'
        }).sort({ createdAt: -1 });

        const tooRecent = last && (now.getTime() - last.createdAt.getTime()) < (6 * 60 * 60 * 1000); // 6 hours
        if (!tooRecent) {
          await recordSecurityEventAndNotify({
            user,
            type: 'late_login',
            severity: 'medium',
            message: `Child account ${user.email} logged in between ${LATE_HOUR_START}:00 and ${LATE_HOUR_END}:00.`,
            details: { hour, ip }
          });
        }
      }
    }

    await user.save();

    // MFA challenge (supports twoFA or mfa)
    if (user.twoFA?.enabled || user.mfa?.enabled) {
      return res.json({ mfaRequired: true, mfaToken: signMfaTempToken(user) });
    }

    const token   = signAuthToken(user);
    const refresh = signRefreshToken(user);
    res.json({ token, accessToken: token, refreshToken: refresh,
      user: { id: user._id, email: user.email, role: user.role, isSuperuser: user.isSuperuser, displayName: user.displayName ?? '' }
    });
  } catch (e) { console.error('login error:', e?.message || e); res.status(503).json({ message: 'Service temporarily unavailable' }); }
});

/* -------- /auth/refresh -------- */
router.post('/refresh', async (req, res) => {
  try {
    const token = bearer(req);
    if (!token) return res.status(401).json({ message: 'No token' });
    const payload = verifyRefreshToken(token);
    const user = await User.findById(payload.sub).select('tokenVersion email role isSuperuser displayName');
    if (!user) return res.status(401).json({ message: 'Invalid user' });
    if ((payload.tv ?? 0) !== (user.tokenVersion ?? 0)) {
      return res.status(401).json({ message: 'Session expired' });
    }
    const newAccess  = signAuthToken(user);
    const newRefresh = signRefreshToken(user);
    res.json({ accessToken: newAccess, refreshToken: newRefresh });
  } catch (e) { console.error('refresh error:', e?.message || e); res.status(401).json({ message: 'Invalid or expired token' }); }
});

/* -------- 2FA: status/setup/enable/verify/disable/rotate/recovery -------- */
router.get('/2fa/status', requireAuth, async (req, res) => {
  const me = await User.findById(req.user._id).select('mfa twoFA');
  res.json({ enabled: !!(me?.twoFA?.enabled || me?.mfa?.enabled) });
});

router.post('/2fa/setup', requireAuth, async (req, res) => {
  const me = await User.findById(req.user._id);
  const secret = speakeasy.generateSecret({ name: `GuardianLink:${me.email}`, length: 20 });

  me.twoFA = { enabled: false, pending: true, secret: secret.base32 };
  me.mfa   = { ...(me.mfa||{}), enabled: false, secret: secret.base32, recoveryCodes: me.mfa?.recoveryCodes || [] };
  await me.save();

  res.json({ otpauth: secret.otpauth_url, qr: await qrcode.toDataURL(secret.otpauth_url) });
});

router.post('/2fa/enable', requireAuth, async (req, res) => {
  try {
    const { code } = req.body || {};
    const user = await User.findById(req.user._id);
    const secret = user?.twoFA?.secret || user?.mfa?.secret;
    if (!secret) return res.status(400).json({ message: '2FA not in setup' });

    const ok = speakeasy.totp.verify({ secret, encoding: 'base32', token: String(code ?? '').replace(/\s+/g, ''), window: 2, step: 30 });
    if (!ok) return res.status(400).json({ message: 'Invalid code' });

    user.twoFA = { enabled: true, pending: false, secret };
    user.mfa   = { ...(user.mfa||{}), enabled: true, secret };
    await user.save();
    res.json({ message: '2FA enabled' });
  } catch (e) { console.error('2fa enable error:', e); res.status(500).json({ message: 'Server error' }); }
});

router.post('/2fa/verify', async (req, res) => {
  try {
    const mfaToken = req.body?.mfaToken;
    const rawCode  = req.body?.code;
    if (!mfaToken || !rawCode) return res.status(400).json({ message: 'mfaToken and code required' });

    let payload;
    try { payload = jwt.verify(mfaToken, ACCESS_SECRET); }
    catch { return res.status(401).json({ message: 'Invalid or expired token' }); }
    if (!payload?.mfa) return res.status(400).json({ message: 'Invalid token type' });

    const user = await User.findById(payload.sub);
    const secret = user?.twoFA?.secret || user?.mfa?.secret;
    if (!(user?.twoFA?.enabled || user?.mfa?.enabled) || !secret) {
      return res.status(400).json({ message: '2FA not enabled' });
    }

    const ok = speakeasy.totp.verify({ secret, encoding: 'base32', token: String(rawCode).replace(/\s+/g, ''), window: 2, step: 30 });
    if (!ok) return res.status(401).json({ message: 'Invalid code' });

    const finalToken = signAuthToken(user);
    const refresh    = signRefreshToken(user);
    res.json({ token: finalToken, accessToken: finalToken, refreshToken: refresh,
      user: { id: user._id, email: user.email, role: user.role, isSuperuser: user.isSuperuser, displayName: user.displayName ?? '' }
    });
  } catch (e) { console.error('2fa verify error:', e); res.status(500).json({ message: 'Server error' }); }
});

router.post('/2fa/disable', requireAuth, async (req, res) => {
  const u = await User.findById(req.user._id);
  if (!u) return res.status(404).json({ message: 'User not found' });
  u.mfa = { enabled: false, secret: null, recoveryCodes: [] };
  u.twoFA = { enabled: false, pending: false, secret: null };
  await u.save();
  res.json({ message: '2FA disabled' });
});

router.post('/2fa/rotate', requireAuth, async (req,res)=>{
  try{
    const { code } = req.body||{};
    const u = await User.findById(req.user._id);
    const sec = u?.twoFA?.secret||u?.mfa?.secret;
    if(!sec) return res.status(400).json({message:'2FA not enabled'});
    const ok = speakeasy.totp.verify({ secret:sec, encoding:'base32', token:String(code??'').replace(/\s+/g,''), window:2, step:30 });
    if(!ok) return res.status(401).json({message:'Invalid code'});
    const nxt = speakeasy.generateSecret({ name:`GuardianLink (${u.email})`, length:20 });
    u.twoFA.secret = nxt.base32; u.mfa.secret = nxt.base32; await u.save();
    res.json({ otpauth: nxt.otpauth_url, qr: await qrcode.toDataURL(nxt.otpauth_url) });
  }catch(e){ console.error('2fa rotate error:',e); res.status(500).json({message:'Server error'}); }
});

router.post('/2fa/recovery/regen', requireAuth, async (req,res)=>{
  const crypto = await import('node:crypto');
  const { code } = req.body||{};
  const u = await User.findById(req.user._id);
  const sec = u?.twoFA?.secret||u?.mfa?.secret;
  if(!sec) return res.status(400).json({message:'2FA not enabled'});
  const ok = speakeasy.totp.verify({ secret:sec, encoding:'base32', token:String(code??'').replace(/\s+/g,''), window:2, step:30 });
  if(!ok) return res.status(401).json({message:'Invalid code'});
  const plain = Array.from({length:10}, ()=>crypto.randomBytes(5).toString('hex'));
  u.mfa.recoveryCodes = plain.map(c=>crypto.createHash('sha256').update(c).digest('hex'));
  await u.save();
  res.json({ recoveryCodes: plain });
});

/* ---------------- Forgot / Reset ---------------- */
router.post('/forgot', forgotLimiter, async (req, res) => {
  try {
    const email = (req.body?.email || '').toString().trim().toLowerCase();
    if (!email) return res.json({ ok: true });  

    const user = await User.findOne({ email });
    if (!user) return res.json({ ok: true });

    const code = String(Math.floor(100000 + Math.random() * 900000));
    user.reset = { code, expires: new Date(Date.now() + RESET_TTL_MIN * 60 * 1000), attempts: 0 };
    await user.save();

    await sendResetCode(email, code, RESET_TTL_MIN);
    if (process.env.NODE_ENV !== 'production') {
      console.log(`🔐 DEV reset code for ${email}: ${code}`);
    }
    res.json({ ok: true });
  } catch (e) {
    console.error('forgot error:', e);
    res.status(500).json({ message: 'Failed to send reset code' });
  }
});

router.post('/reset', validate(schemas.reset), async (req, res) => {
  try {
    const email       = (req.body?.email || '').trim().toLowerCase();
    const code        = (req.body?.code || '').trim();
    const newPassword = (req.body?.newPassword || '').trim();

    const user = await User.findOne({ email });
    if (!user?.reset?.code) return res.status(400).json({ message: 'No active reset' });

    if (user.reset.expires < new Date()) {
      user.reset = undefined; await user.save();
      return res.status(400).json({ message: 'Code expired' });
    }

    if (user.reset.attempts >= MAX_RESET_ATTEMPTS) {
      user.reset = undefined; await user.save();
      return res.status(423).json({ message: 'Too many attempts' });
    }

    if (code !== user.reset.code) {
      user.reset.attempts += 1; await user.save();
      return res.status(401).json({ message: 'Invalid code' });
    }

    // Enforce password strength (Option B)
    if (!meetsPasswordPolicy(newPassword)) {
      return res.status(400).json({
        message: 'Weak password. Min 10 chars and at least 2 of: uppercase, lowercase, number, symbol.'
      });
    }


    user.passwordHash = await bcrypt.hash(newPassword, 12);
    user.reset = undefined;

    // reset login attempts & lock on successful password reset
    user.loginSecurity = user.loginSecurity || {};
    user.loginSecurity.attempts = 0;
    user.loginSecurity.lockedUntil = null;

    user.tokenVersion = (user.tokenVersion || 0) + 1; // invalidate all old tokens
    await user.save();

    res.json({ ok: true });
  } catch (e) {
    console.error('reset error:', e);
    res.status(500).json({ message: 'Failed to reset password' });
  }
});

// POST /auth/verify/start
router.post('/verify/start', requireAuth, async (req, res) => {
  const me = await User.findById(req.user._id || req.user.id);
  if (!me) return res.status(404).json({ message: 'User not found' });

  const code = String(Math.floor(100000 + Math.random() * 900000)).slice(-6);
  // 10-min code
  me.reset = { code, expires: new Date(Date.now() + 10*60*1000), attempts: 0 };

  // 48-hour grace for unverified parents
  if (!me.emailVerified) {
    const graceMs = 48 * 60 * 60 * 1000;
    me.verify = { expires: me.verify?.expires || new Date(Date.now() + graceMs) };
  }

  await me.save();
  await sendVerifyCode(me.email, code);
  res.json({ ok: true });
});

// POST /auth/verify/confirm
router.post('/verify/confirm', requireAuth, async (req, res) => {
  try {
    const me = await User.findById(req.user._id || req.user.id);
    if (!me) return res.status(404).json({ message: 'User not found' });

    const code = String(req.body?.code || '').trim();
    const r = me.reset || {};
    const valid = r.code && r.expires && new Date(r.expires) > new Date();
    if (!valid || code !== r.code) {
      return res.status(400).json({ message: 'Invalid or expired code' });
    }

    me.emailVerified = true;
    me.reset = undefined;
    await me.save();
    res.json({ ok: true });
  } catch (e) {
    console.error('verify/confirm error:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

export default router;