// src/routes/admin.js
import { Router } from 'express';
import bcrypt from 'bcrypt';
import mongoose from 'mongoose';
import User from '../models/User.js';
import { requireAuth, requireSuperuser } from '../middleware/authz.js';

const router = Router();

async function ensureFamilyIdFor(userId) {
  const me = await User.findById(userId);
  if (!me) throw Object.assign(new Error('User not found'), { status: 404 });
  if (!me.familyId) {
    me.familyId = new mongoose.Types.ObjectId();
    await me.save();
  }
  return me.familyId;
}

// Password policy: min 10 chars + at least 2 of [upper, lower, digit, symbol]
function meetsPasswordPolicy(password) {
  if (typeof password !== 'string' || password.length < 10) return false;

  let hasUpper = false;
  let hasLower = false;
  let hasDigit = false;
  let hasSymbol = false;

  for (const ch of password) {
    if (/[A-Z]/.test(ch)) hasUpper = true;
    else if (/[a-z]/.test(ch)) hasLower = true;
    else if (/[0-9]/.test(ch)) hasDigit = true;
    else hasSymbol = true;
  }

  const categories = [hasUpper, hasLower, hasDigit, hasSymbol].filter(Boolean).length;
  return categories >= 2;
}


/* -------- GET /admin/family -------- */
router.get('/family', requireAuth, async (req, res) => {
  try {
    const familyId = await ensureFamilyIdFor(req.user._id);

    const parents  = await User.find({ familyId, role: 'Parent' })
      .select('_id email displayName role isSuperuser');
    const children = await User.find({ familyId, role: 'Child'  })
      .select('_id email displayName role parentId');

    res.json({
      parents: parents.map(u => ({
        id: u._id, email: u.email, displayName: u.displayName,
        role: u.role, isSuperuser: u.isSuperuser
      })),
      children: children.map(u => ({
        id: u._id, email: u.email, displayName: u.displayName,
        role: u.role, parentId: u.parentId
      }))
    });
  } catch (e) {
    console.error('family error:', e);
    res.status(500).json({ message: 'Failed to load family' });
  }
});

/* -------- POST /admin/parents (superuser) -------- */
router.post('/parents', requireAuth, requireSuperuser, async (req, res) => {
  try {
    const { email, password, displayName, isSuperuser } = req.body || {};
    if (!email || !password) return res.status(400).json({ message: 'email and password required' });

    const emailNorm = email.trim().toLowerCase();
    if (await User.findOne({ email: emailNorm })) return res.status(409).json({ message: 'Email already exists' });

    if (!meetsPasswordPolicy(password)) {
      return res.status(400).json({
        message: 'Weak password. Min 10 chars and at least 2 of: uppercase, lowercase, number, symbol.'
      });
    }
    
    const familyId = await ensureFamilyIdFor(req.user._id);
    const passwordHash = await bcrypt.hash(password, 12);
    const parent = await User.create({
      email: emailNorm,
      passwordHash,
      role: 'Parent',
      isSuperuser: !!isSuperuser,
      familyId,
      displayName: (displayName || '').trim() || emailNorm.split('@')[0]
    });
    res.status(201).json({ id: parent._id });
  } catch (e) {
    console.error('create parent error:', e);
    res.status(500).json({ message: 'Failed to create parent' });
  }
});

/* -------- POST /admin/children (parent or superuser) -------- */
router.post('/children', requireAuth, async (req, res) => {
  try {
    if (req.user.role !== 'Parent') return res.status(403).json({ message: 'Parents only' });
    const { email, password, displayName } = req.body || {};
    if (!email || !password) return res.status(400).json({ message: 'email and password required' });

    const emailNorm = email.trim().toLowerCase();
    if (await User.findOne({ email: emailNorm })) return res.status(409).json({ message: 'Email already exists' });

    if (!meetsPasswordPolicy(password)) {
      return res.status(400).json({
        message: 'Weak password. Min 10 chars and at least 2 of: uppercase, lowercase, number, symbol.'
      });
    }

    const familyId = await ensureFamilyIdFor(req.user._id);
    
    const child = await User.create({
      email: emailNorm,
      passwordHash: await bcrypt.hash(password, 12),
      role: 'Child',
      familyId,
      parentId: req.user._id,
      displayName: (displayName || '').trim() || null
    });

    res.status(201).json({ id: child._id });
  } catch (e) {
    console.error('create child error:', e);
    res.status(500).json({ message: 'Failed to create child' });
  }
});

/* ---------- POST /admin/parents/link (SU only) ---------- */
/* Moves target parent (and their whole household) into caller's family if different. */
router.post('/parents/link', requireAuth, requireSuperuser, async (req, res) => {
  console.log('[LINK-PARENT] hit:', req.method, req.originalUrl);
  try {
    const emailNorm = String(req.body?.email || '').trim().toLowerCase();
    if (!emailNorm) return res.status(400).json({ message: 'email required' });

    const target = await User.findOne({ email: emailNorm, role: 'Parent' });
    if (!target) return res.status(404).json({ message: 'Parent not found' });

    const callerFamily = String(req.user.familyId || '');
    const targetFamily = String(target.familyId || '');

    if (targetFamily === callerFamily) {
      if (target.isSuperuser && req.user.isSuperuser) {
        target.isSuperuser = false;
        await target.save();
      }
      return res.json({ ok: true, message: 'Already linked' });
    }

    if (target.familyId && targetFamily !== callerFamily) {
      const oldFam = target.familyId;
      const newFam = req.user.familyId;

      const session = await mongoose.startSession();
      try {
        await session.withTransaction(async () => {
          await User.updateMany(
            { familyId: oldFam, isSuperuser: true },
            { $set: { isSuperuser: false } },
            { session }
          );

          await User.updateMany(
            { familyId: oldFam },
            { $set: { familyId: newFam } },
            { session }
          );

          const destHasSU = await User.exists({ familyId: newFam, isSuperuser: true }).session(session);
          if (destHasSU && target.isSuperuser) {
            await User.updateOne({ _id: target._id }, { $set: { isSuperuser: false } }, { session });
          }
        });

        return res.json({ ok: true, message: 'Household moved and parent linked' });
      } catch (e) {
        console.error('[LINK-PARENT] migrate failed:', e);
        return res.status(500).json({ message: 'Failed to migrate household' });
      } finally {
        await session.endSession();
      }
    }

    // target had no familyId → just link
    const destHasSU = await User.exists({ familyId: req.user.familyId, isSuperuser: true });
    target.familyId = req.user.familyId;
    if (destHasSU && target.isSuperuser) target.isSuperuser = false;
    await target.save();

    return res.json({ ok: true, message: 'Parent linked to your family' });
  } catch (e) {
    console.error('link parent error:', e);
    res.status(500).json({ message: 'Failed to link parent' });
  }
});

/* -------- DELETE /admin/users/:id (superuser) -------- */
router.delete('/users/:id', requireAuth, requireSuperuser, async (req, res) => {
  try {
    const target = await User.findById(req.params.id);
    if (!target) return res.status(404).json({ message: 'User not found' });
    if (String(target.familyId) !== String(req.user.familyId)) {
      return res.status(403).json({ message: 'Different family' });
    }
    if (target.role === 'Parent' && target.isSuperuser) {
      return res.status(400).json({ message: 'Cannot delete superuser' });
    }
    await target.deleteOne();
    res.json({ ok: true });
  } catch (e) {
    console.error('delete user error:', e);
    res.status(500).json({ message: 'Failed to delete user' });
  }
});

/* -------- POST /admin/superuser/transfer (superuser) -------- */
router.post('/superuser/transfer', requireAuth, requireSuperuser, async (req, res) => {
  try {
    const { targetParentId } = req.body || {};
    if (!targetParentId) return res.status(400).json({ message: 'targetParentId required' });

    const me = await User.findById(req.user._id);
    const target = await User.findById(targetParentId);
    if (!target || target.role !== 'Parent') return res.status(404).json({ message: 'Target not found' });

    // normalize legacy: unify into one family if either is missing familyId
    if (!me.familyId && !target.familyId) me.familyId = new mongoose.Types.ObjectId();
    if (!target.familyId) target.familyId = me.familyId;
    if (!me.familyId) me.familyId = target.familyId;
    await Promise.all([me.save(), target.save()]);

    if (String(target.familyId) !== String(me.familyId)) {
      return res.status(403).json({ message: 'Different family' });
    }

    // demote current SU, promote target, bump tokenVersion so old tokens die (forces logout)
    await User.updateOne({ _id: me._id },     { $set: { isSuperuser: false }, $inc: { tokenVersion: 1 } });
    await User.updateOne({ _id: target._id }, { $set: { isSuperuser: true  }, $inc: { tokenVersion: 1 } });

    res.json({ ok: true, message: 'Superuser transferred' });
  } catch (e) {
    console.error('transfer su error:', e);
    res.status(500).json({ message: 'Failed to transfer' });
  }
});

export default router;