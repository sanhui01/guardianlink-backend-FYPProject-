// src/utils/jwt.js
import jwt from 'jsonwebtoken';

const ACCESS_SECRET  = process.env.JWT_SECRET || 'dev-secret';
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'dev-refresh';

export function signAuthToken(user) {
  return jwt.sign(
    {
      sub: user._id.toString(),
      email: user.email,
      role: user.role,
      su: !!user.isSuperuser,
      tv: user.tokenVersion ?? 0
    },
    ACCESS_SECRET,
    { expiresIn: '30m' }
  );
}

export function signRefreshToken(user) {
  return jwt.sign(
    { sub: user._id.toString(), tv: user.tokenVersion ?? 0 },
    REFRESH_SECRET,
    { expiresIn: '30d' }
  );
}

export function verifyAuthToken(token) {
  return jwt.verify(token, ACCESS_SECRET);
}

export function verifyRefreshToken(token) {
  return jwt.verify(token, REFRESH_SECRET);
}

/* ORIGINAL kept in /mnt/data/jwt.js */


// // src/utils/jwt.js
// import jwt from 'jsonwebtoken';

// const ACCESS_SECRET  = process.env.JWT_SECRET || 'dev-secret';
// const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'dev-refresh';
// const ACCESS_TTL     = process.env.JWT_ACCESS_TTL || '15m';
// const REFRESH_TTL    = process.env.JWT_REFRESH_TTL || '7d';

// export function signAuthToken(user) {
//   // include tokenVersion to support global logout / password reset invalidation
//   const payload = { sub: user._id.toString(), tv: user.tokenVersion || 0 };
//   return jwt.sign(payload, ACCESS_SECRET, { expiresIn: ACCESS_TTL });
// }

// export function signRefreshToken(user) {
//   const payload = { sub: user._id.toString(), tv: user.tokenVersion || 0 };
//   return jwt.sign(payload, REFRESH_SECRET, { expiresIn: REFRESH_TTL });
// }

// export function verifyAuthToken(token) {
//   return jwt.verify(token, ACCESS_SECRET);
// }

// export function verifyRefreshToken(token) {
//   return jwt.verify(token, REFRESH_SECRET);
// }
