import bcrypt from 'bcryptjs';
import { User } from '../models/User.js';  // your existing user model

function assertSuper(req) {
  if (req.user.role !== 'Parent' || !req.user.isSuperuser) {
    const err = new Error('Only superuser parent can perform this action.');
    err.status = 403;
    throw err;
  }
}

// List family members (parents + children)
export async function getFamily(req, res, next) {
  try {
    assertSuper(req);
    const superId = req.user.id;

    const parents = await User.find({ role: 'Parent', $or: [{ _id: superId }, { parentId: superId }] })
      .select('_id email displayName isSuperuser role createdAt');

    const children = await User.find({ role: 'Child', parentId: superId })
      .select('_id email displayName role createdAt');

    res.json({ parents, children });
  } catch (e) { next(e); }
}

// Invite an additional Parent (creates inactive parent with random pwd)
export async function inviteParent(req, res, next) {
  try {
    assertSuper(req);
    const { email, displayName } = req.body || {};
    if (!email) throw Object.assign(new Error('Email is required'), { status: 400 });

    const exists = await User.findOne({ email });
    if (exists) throw Object.assign(new Error('Email already exists'), { status: 400 });

    const hash = await bcrypt.hash(Math.random().toString(36).slice(2, 10), 12);
    const user = await User.create({
      email, passwordHash: hash, role: 'Parent',
      parentId: req.user.id, displayName: displayName || ''
    });

    // (Optionally send invite mail with reset link)
    res.json({ ok: true, user: { id: user._id, email: user.email, displayName: user.displayName } });
  } catch (e) { next(e); }
}

export async function removeParent(req, res, next) {
  try {
    assertSuper(req);
    const { id } = req.params;
    if (String(id) === String(req.user.id)) {
      throw Object.assign(new Error('Use /admin/me to delete your own account.'), { status: 400 });
    }
    const target = await User.findById(id);
    if (!target || target.role !== 'Parent') throw Object.assign(new Error('Parent not found'), { status: 404 });
    if (target.isSuperuser) throw Object.assign(new Error('Transfer superuser first.'), { status: 400 });

    // Reassign children of the removed parent to superuser if needed
    await User.updateMany({ role: 'Child', parentId: target._id }, { parentId: req.user.id });

    await target.deleteOne();
    res.json({ ok: true });
  } catch (e) { next(e); }
}

export async function transferSuperuser(req, res, next) {
  try {
    assertSuper(req);
    const { toParentId } = req.body || {};
    const target = await User.findById(toParentId);
    if (!target || target.role !== 'Parent') throw Object.assign(new Error('Target parent not found'), { status: 404 });

    await User.updateOne({ _id: req.user.id }, { isSuperuser: false });
    await User.updateOne({ _id: target._id }, { isSuperuser: true });

    res.json({ ok: true });
  } catch (e) { next(e); }
}

export async function removeChild(req, res, next) {
  try {
    assertSuper(req);
    const { id } = req.params;
    const child = await User.findById(id);
    if (!child || child.role !== 'Child') throw Object.assign(new Error('Child not found'), { status: 404 });
    if (String(child.parentId) !== String(req.user.id)) {
      throw Object.assign(new Error('Child not in your family'), { status: 403 });
    }
    await child.deleteOne();
    res.json({ ok: true });
  } catch (e) { next(e); }
}

export async function resetChildPassword(req, res, next) {
  try {
    assertSuper(req);
    const { id } = req.params;
    const { newPassword } = req.body || {};
    const child = await User.findById(id);
    if (!child || child.role !== 'Child') throw Object.assign(new Error('Child not found'), { status: 404 });
    if (String(child.parentId) !== String(req.user.id)) {
      throw Object.assign(new Error('Child not in your family'), { status: 403 });
    }
    const hash = await bcrypt.hash(newPassword || '123456', 12);
    child.passwordHash = hash;
    await child.save();
    res.json({ ok: true });
  } catch (e) { next(e); }
}

export async function deleteMe(req, res, next) {
  try {
    assertSuper(req);
    const others = await User.countDocuments({ role: 'Parent', parentId: req.user.id });
    if (others > 0) {
      throw Object.assign(new Error('Transfer superuser and reassign family first.'), { status: 400 });
    }
    await User.deleteOne({ _id: req.user.id });
    res.json({ ok: true });
  } catch (e) { next(e); }
}

// POST /admin/parents/link  { email }
export const linkExistingParent = async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    if (!email) return res.status(400).json({ message: 'Email required' });

    const target = await User.findOne({ email, role: 'Parent' });
    if (!target) return res.status(404).json({ message: 'Parent not found' });

    // 409 if belongs to another family
    if (target.familyId && String(target.familyId) !== String(req.user.familyId)) {
      return res.status(409).json({ message: 'Parent belongs to another family' });
    }

    target.familyId = req.user.familyId;
    await target.save();

    res.json({
      ok: true,
      parent: {
        id: target._id,
        email: target.email,
        displayName: target.displayName,
        familyId: target.familyId
      }
    });
  } catch (e) {
    console.error('linkExistingParent error:', e);
    res.status(500).json({ message: 'Server error' });
  }
};

