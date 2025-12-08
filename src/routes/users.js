import { Router } from 'express';
import User from '../models/User.js';
import { requireAuth , requireParent} from '../middleware/authz.js';
import { schemas, validate } from '../middleware/validators.js';

const router = Router();

/**
 * POST /users
 * Parent creates a Child account (no email verification flow here, by design).
 * Body: { email, password }
 */
router.post('/', requireAuth, requireParent, validate(schemas.createChild), async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    const exists = await User.findOne({ email });
    if (exists) return res.status(409).json({ message: 'Account already exists' });

    const passwordHash = await User.hashPassword(password);
     // IMPORTANT: set child's familyId to parent's familyId
    const child = await User.create({
      email,
      passwordHash,
      role: 'Child',
      parentId: req.user._id,
      familyId: req.user.familyId,               
      displayName: (req.body.displayName || '').trim() || null,
      tokenVersion: 0,
      twoFA: { enabled: false, pending: false },
      mfa:   { enabled: false, secret: null, recoveryCodes: [] },
      emailVerified: false
    });

    return res.status(201).json({
      user: {
        id: child._id,
        email: child.email,
        role: child.role,
        parentId: child.parentId,
      }
    });
  } catch (e) {
    console.error('create child error:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

/**
 * DELETE /users/:id
 * - Superuser can delete anyone
 * - Parent can delete their own children
 */
router.delete('/:id', requireAuth, async (req, res) => {
  try {
    const target = await User.findById(req.params.id);
    if (!target) return res.status(404).json({ message: 'Not found' });

    const isOwnerParent = req.user.role === 'Parent' && String(target.parentId || '') === String(req.user._id);
    const isSuper = !!req.user.isSuperuser;

    if (!isSuper && !isOwnerParent) {
      return res.status(403).json({ message: 'Not allowed' });
    }

    await target.deleteOne();
    return res.json({ ok: true });
  } catch (e) {
    console.error('delete user error:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

/**
 * DELETE /users/me
 * Any user can delete their own account.
 * (If the last superuser is deleted, your existing "first parent gets superuser" rule
 * will promote the next parent who registers, which is acceptable per your spec.)
 */
router.delete('/me/self', requireAuth, async (req, res) => {
  try {
    await req.user.deleteOne();
    return res.json({ ok: true });
  } catch (e) {
    console.error('self delete error:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

router.patch('/me', requireAuth, async (req, res) => {
  try {
    const dn = String(req.body?.displayName || '').trim();
    if (dn.length < 1 || dn.length > 40) {
      return res.status(400).json({ message: 'displayName must be 1–40 chars' });
    }
    await User.updateOne({ _id: req.user._id }, { $set: { displayName: dn } });
    res.json({ ok: true, displayName: dn });
  } catch (e) {
    console.error('update me error:', e);
    res.status(500).json({ message: 'Failed to update profile' });
  }
});

router.get('/family', requireAuth, async (req, res, next) => {
  try {
    // Try to load the current user to get their familyId
    const me = await User.findById(req.user._id).lean();
    if (!me) {
      return res.status(404).json({ message: 'User not found' });
    }

    const familyId = me.familyId || req.user.familyId;
    if (!familyId) {
      // User not assigned to any family yet
      return res.json({
        parents: [],
        children: [],
      });
    }

    // Load all parents & children in the same family
    const [parents, children] = await Promise.all([
      User.find({ familyId, role: 'Parent' }).lean(),
      User.find({ familyId, role: 'Child' }).lean(),
    ]);

    const mapUser = (u) => ({
      id: String(u._id),
      email: u.email || '',
      displayName: u.displayName || '',
      role: u.role || '',
      isSuperuser: !!u.isSuperuser,
      parentId: u.parentId ? String(u.parentId) : null,
    });

    return res.json({
      parents: parents.map(mapUser),
      children: children.map(mapUser),
    });
  } catch (e) {
    next(e);
  }
});

export default router;
