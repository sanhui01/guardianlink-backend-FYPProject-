// src/routes/security.js
import { Router } from 'express';
import User from '../models/User.js';
import SecurityEvent from '../models/SecurityEvent.js';
import { requireAuth } from '../middleware/authz.js';

const router = Router();

/**
 * GET /security/events
 * List recent security events for the current user's family.
 * Parents see all; children see only their own.
 */
router.get('/events', requireAuth, async (req, res) => {
  try {
    const me = await User.findById(req.user._id).select('familyId role');
    if (!me) return res.status(404).json({ message: 'User not found' });

    const query = { familyId: me.familyId };
    if (me.role === 'Child') {
      query.userId = me._id;
    }

    const events = await SecurityEvent.find(query)
      .sort({ createdAt: -1 })
      .limit(50)
      .lean();

    res.json({ events });
  } catch (e) {
    console.error('security events error:', e);
    res.status(500).json({ message: 'Failed to load security events' });
  }
});

/**
 * GET /security/devices
 * List linked devices (sessions) for current user.
 */
router.get('/devices', requireAuth, async (req, res) => {
  try {
    const me = await User.findById(req.user._id).select('sessions deviceLimits role');
    if (!me) return res.status(404).json({ message: 'User not found' });

    res.json({
      maxDevices: me.deviceLimits?.maxDevices || (me.role === 'Child' ? 2 : 3),
      sessions: (me.sessions || []).map(s => ({
        deviceId: s.deviceId,
        deviceName: s.deviceName,
        platform: s.platform,
        firstSeenAt: s.firstSeenAt,
        lastSeenAt: s.lastSeenAt,
        lastIp: s.lastIp
      }))
    });
  } catch (e) {
    console.error('security devices error:', e);
    res.status(500).json({ message: 'Failed to load devices' });
  }
});

/**
 * POST /security/devices/remove
 * Body: { deviceId }
 * Removes a session for current user and bumps tokenVersion to kick that device.
 */
router.post('/devices/remove', requireAuth, async (req, res) => {
  try {
    const { deviceId } = req.body || {};
    if (!deviceId) return res.status(400).json({ message: 'deviceId required' });

    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    const before = user.sessions?.length || 0;
    user.sessions = (user.sessions || []).filter(s => s.deviceId !== deviceId);

    if (user.sessions.length === before) {
      return res.status(404).json({ message: 'Device not found' });
    }

    // bump tokenVersion to ensure any old token on this user dies
    user.tokenVersion = (user.tokenVersion || 0) + 1;
    await user.save();

    res.json({ ok: true });
  } catch (e) {
    console.error('remove device error:', e);
    res.status(500).json({ message: 'Failed to remove device' });
  }
});

/**
 * POST /security/devices/limits
 * Parent can adjust maxDevices for their own account (later: for children).
 */
router.post('/devices/limits', requireAuth, async (req, res) => {
  try {
    const { maxDevices } = req.body || {};
    const v = Number(maxDevices);
    if (!Number.isInteger(v) || v < 1 || v > 5) {
      return res.status(400).json({ message: 'maxDevices must be 1–5' });
    }

    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    user.deviceLimits = user.deviceLimits || {};
    user.deviceLimits.maxDevices = v;
    await user.save();

    res.json({ ok: true, maxDevices: v });
  } catch (e) {
    console.error('set device limits error:', e);
    res.status(500).json({ message: 'Failed to update device limits' });
  }
});

// Add near the bottom of security.js, before export default

/**
 * GET /security/devices/family
 * Parent: see all children in the same family with their sessions.
 */
router.get('/devices/family', requireAuth, async (req, res) => {
  try {
    const me = await User.findById(req.user._id).select('role familyId');
    if (!me) return res.status(404).json({ message: 'User not found' });
    if (me.role !== 'Parent') {
      return res.status(403).json({ message: 'Parents only' });
    }

    const children = await User.find({
      familyId: me.familyId,
      role: 'Child'
    }).select('_id email displayName sessions deviceLimits');

    const payload = children.map(c => ({
      id: c._id,
      email: c.email,
      displayName: c.displayName,
      maxDevices: c.deviceLimits?.maxDevices ?? 2,
      sessions: (c.sessions || []).map(s => ({
        deviceId: s.deviceId,
        deviceName: s.deviceName,
        platform: s.platform,
        firstSeenAt: s.firstSeenAt,
        lastSeenAt: s.lastSeenAt,
        lastIp: s.lastIp
      }))
    }));

    res.json({ children: payload });
  } catch (e) {
    console.error('family devices error:', e);
    res.status(500).json({ message: 'Failed to load family devices' });
  }
});

/**
 * POST /security/devices/child/remove
 * Body: { childId, deviceId }
 * Parent can revoke one device session belonging to a child.
 */
router.post('/devices/child/remove', requireAuth, async (req, res) => {
  try {
    const { childId, deviceId } = req.body || {};
    if (!childId || !deviceId) {
      return res.status(400).json({ message: 'childId and deviceId required' });
    }

    const me = await User.findById(req.user._id).select('role familyId');
    if (!me) return res.status(404).json({ message: 'User not found' });
    if (me.role !== 'Parent') {
      return res.status(403).json({ message: 'Parents only' });
    }

    const child = await User.findById(childId);
    if (!child || child.role !== 'Child') {
      return res.status(404).json({ message: 'Child not found' });
    }
    if (String(child.familyId) !== String(me.familyId)) {
      return res.status(403).json({ message: 'Different family' });
    }

    const before = child.sessions?.length || 0;
    child.sessions = (child.sessions || []).filter(s => s.deviceId !== deviceId);

    if (child.sessions.length === before) {
      return res.status(404).json({ message: 'Device not found' });
    }

    child.tokenVersion = (child.tokenVersion || 0) + 1;
    await child.save();

    res.json({ ok: true });
  } catch (e) {
    console.error('remove child device error:', e);
    res.status(500).json({ message: 'Failed to remove child device' });
  }
});

/**
 * POST /security/devices/child/limits
 * Parent adjusts maxDevices for child
 * Body: { childId, maxDevices }
 */
router.post('/devices/child/limits', requireAuth, async (req, res) => {
  try {
    const { childId, maxDevices } = req.body || {};
    const v = Number(maxDevices);

    if (!childId || !Number.isInteger(v) || v < 1 || v > 5) {
      return res.status(400).json({ message: "childId and valid maxDevices (1–5) required" });
    }

    const me = await User.findById(req.user._id).select("role familyId");
    if (!me || me.role !== "Parent") {
      return res.status(403).json({ message: "Parents only" });
    }

    const child = await User.findById(childId);
    if (!child || child.role !== "Child") {
      return res.status(404).json({ message: "Child not found" });
    }

    if (String(child.familyId) !== String(me.familyId)) {
      return res.status(403).json({ message: "Different family" });
    }

    child.deviceLimits = child.deviceLimits || {};
    child.deviceLimits.maxDevices = v;
    await child.save();

    res.json({ ok: true, maxDevices: v });
  } catch (e) {
    console.error("child limit update error:", e);
    res.status(500).json({ message: "Failed to update child limit" });
  }
});


export default router;
