import { Router } from "express";
import { body, validationResult } from "express-validator";
import { requireAuth } from "../middleware/authz.js";
import PushToken from "../models/PushToken.js";

const r = Router();

const v = (req, res) => {
  const e = validationResult(req);
  if (!e.isEmpty()) {
    res.status(400).json({ errors: e.array() });
    return false;
  }
  return true;
};

r.post(
  "/register",
  requireAuth,
  body("deviceId").isString().trim().isLength({ min: 1 }),
  body("fcmToken").isString().trim().isLength({ min: 10 }),
  body("platform").optional().isString().trim(),
  async (req, res, next) => {
    try {
      if (!v(req, res)) return;

      const { deviceId, fcmToken } = req.body;
      const platform = req.body.platform || "android";
      // Clean old mappings for this FCM token (IMPORTANT)
await PushToken.deleteMany({ fcmToken });

// Clean old tokens for this deviceId (optional but recommended)
await PushToken.deleteMany({ deviceId });

      const doc = await PushToken.findOneAndUpdate(
  { userId: req.user._id, deviceId },
  {
    $set: {
      userId: req.user._id,
      familyId: req.user.familyId || null,
      role: req.user.role,
      deviceId,
      fcmToken,
      platform,
      updatedAt: new Date(),
    },
    $setOnInsert: { createdAt: new Date() },
  },
  { upsert: true, new: true }
).lean();

      return res.json({ ok: true, id: doc._id });
    } catch (e) {
      next(e);
    }
  }
);

r.post(
  "/unregister",
  requireAuth,
  body("deviceId").isString().trim().isLength({ min: 1 }),
  async (req, res, next) => {
    try {
      if (!v(req, res)) return;
      await PushToken.deleteOne({ userId: req.user._id, deviceId: req.body.deviceId });
      return res.json({ ok: true });
    } catch (e) {
      next(e);
    }
  }
);

export default r;
