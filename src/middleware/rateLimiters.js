// src/middleware/rateLimiters.js
import rateLimit from 'express-rate-limit';

const windowMs = 60 * 1000;

// helper that handles IPv4/IPv6 properly (matches express-rate-limit guidance)
export function ipKeyGenerator(req) {
  // trust proxy should be configured at app level if behind proxy/CDN
  const ip = req.ip || req.connection?.remoteAddress || '';
  return ip;
}

// General limiter (per IP)
export const generalLimiter = rateLimit({
  windowMs,
  max: Number(process.env.RATE_MAX_PER_MIN || 60),
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req, _res) => ipKeyGenerator(req),
});

// Login limiter (per IP + per email)
export const loginLimiter = rateLimit({
  windowMs,
  max: Number(process.env.RATE_LOGIN_MAX_PER_MIN || 10),
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req, _res) => {
    const email = (req.body?.email || '').toString().trim().toLowerCase();
    return `${ipKeyGenerator(req)}:${email}`;
  },
});

// Forgot-password limiter (per IP + per email)
export const forgotLimiter = rateLimit({
  windowMs,
  max: Number(process.env.RATE_FORGOT_MAX_PER_MIN || 5),
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req, _res) => {
    const email = (req.body?.email || '').toString().trim().toLowerCase();
    return `${ipKeyGenerator(req)}:${email}`;
  },
});

export const generalLimiterWithSkip = rateLimit({
  windowMs,
  max: Number(process.env.RATE_MAX_PER_MIN || 300),
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req, _res) => ipKeyGenerator(req),
  skip: (req) => {
    //  NOT TO LIMIT voice streaming
    if (req.path.startsWith("/chat/media")) return true;

    // also skip tick
    if (req.path.startsWith("/api/screen-time/tick")) return true;

    return false;
  },
});