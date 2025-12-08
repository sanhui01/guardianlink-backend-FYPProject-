// src/middleware/authz.js
import User from '../models/User.js';
import { verifyAuthToken } from '../utils/jwt.js';

export async function requireAuth(req, res, next) {
  try {
    const h = req.headers.authorization || '';
    const token = h.startsWith('Bearer ') ? h.slice(7) : null;
    if (!token) return res.status(401).json({ message: 'No token' });

    const payload = verifyAuthToken(token);
    const user = await User.findById(payload.sub)
      .select('_id email role isSuperuser tokenVersion familyId displayName');
    if (!user) return res.status(401).json({ message: 'Invalid user' });

    if ((payload.tv ?? 0) !== (user.tokenVersion ?? 0)) {
      return res.status(401).json({ message: 'Session expired' });
    }

    req.user = {
      _id: user._id,
      id: user._id.toString(),
      email: user.email,
      role: user.role,
      isSuperuser: user.isSuperuser,
      familyId: user.familyId
    };
    next();
  } catch (e){
    console.error('requireAuth error:', e?.message || e);
  return res.status(401).json({ message: 'Invalid token' });
  }
}

export function requireParent(req, res, next) {
  if (req.user?.role === 'Parent') return next();
  return res.status(403).json({ message: 'Parent role required' });
}

export function requireSuperuser(req, res, next) {
  if (req.user?.role === 'Parent' && req.user?.isSuperuser === true) return next();
  return res.status(403).json({ message: 'Superuser required' });
}