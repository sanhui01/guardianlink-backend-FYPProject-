// src/routes/remote.js
import { Router } from "express";
import { body, param, query, validationResult } from "express-validator";
import { requireAuth, requireParent } from "../middleware/authz.js";
import RemoteSession from "../models/RemoteSession.js";
import User from "../models/User.js";
import PushToken from "../models/PushToken.js";
import { sendPushToTokens } from "../utils/push.js";
import RemoteState from "../models/RemoteState.js";

const r = Router();

const v = (req, res) => {
  const e = validationResult(req);
  if (!e.isEmpty()) {
    res.status(400).json({ errors: e.array() });
    return false;
  }
  return true;
};

// Helper: ensure child belongs to same family as parent
async function assertFamilyChild(parent, childId) {
  const child = await User.findOne({ _id: childId, role: "Child" }).lean();
  if (!child) {
    const err = new Error("Child not found");
    err.status = 404;
    throw err;
  }
  if (String(child.familyId || "") !== String(parent.familyId || "")) {
    const err = new Error("Child not in your family");
    err.status = 403;
    throw err;
  }
  return child;
}

// Helper: fetch child's device tokens
async function getChildTokens(childId) {
  const tokens = await PushToken.find({ userId: childId }).distinct("fcmToken");
  return tokens;
}

// ---------- POST /remote/start ----------
r.post(
  "/start",
  requireAuth,
  requireParent,
  body("childId").isString().notEmpty(),
  async (req, res, next) => {
    try {
      if (!v(req, res)) return;

      const parent = req.user;
      const childId = req.body.childId;

      const child = await assertFamilyChild(parent, childId);

      // reset remote flags whenever a new session starts
      await RemoteState.findOneAndUpdate(
        { childId: child._id },
        { locked: false, pauseNet: false, forceLockUntil: null, controlGranted: false },
        { upsert: true }
      );

      const session = await RemoteSession.create({
        familyId: parent.familyId,
        parentId: parent._id,
        childId: child._id,
        controlGranted: false,        // explicit, in case schema default
      });

      res.json({
        sessionId: String(session._id),
        childId: String(session.childId),
        startedAt: session.startedAt,
      });
    } catch (e) {
      next(e);
    }
  }
);

// ---------- POST /remote/:id/command ----------
r.post(
  "/:id/command",
  requireAuth,
  requireParent,
  param("id").isString().notEmpty(),
  body("type")
    .isString()
    .isIn([
      "LOCK",
      "UNLOCK",
      "PAUSE_NET",
      "RESUME_NET",
      "GRANT_CONTROL",
      "REVOKE_CONTROL",
      "FORCE_LOCK",
    ]),
  body("payload").optional().isObject(),
  async (req, res, next) => {
    try {
      if (!v(req, res)) return;

      const parent = req.user;
      const { id } = req.params;
      const { type, payload = {} } = req.body;

      const session = await RemoteSession.findById(id);
      if (!session) {
        return res.status(404).json({ message: "Session not found" });
      }

      // Ensure same family + parent
      if (
        String(session.familyId || "") !== String(parent.familyId || "") ||
        String(session.parentId || "") !== String(parent._id || "")
      ) {
        return res.status(403).json({ message: "Not your session" });
      }

      if (session.endedAt) {
        return res.status(400).json({ message: "Session already ended" });
      }

      // --- 1) Update controlGranted when parent presses Grant / Revoke ---

      if (type === "GRANT_CONTROL") {
  // Parent is requesting control; mark on the session
  session.controlGranted = true;
} else if (type === "REVOKE_CONTROL") {
  // Parent revokes control → clear everything
  session.controlGranted = false;
  await RemoteState.findOneAndUpdate(
    { childId: session.childId },
    {
      locked: false,
      pauseNet: false,
      forceLockUntil: null,
      controlGranted: false,
    },
    { upsert: true }
  );
}

      // --- 2) Only some commands require full handshake ---
      // FORCE_LOCK is allowed even without grant (emergency override)
const commandsRequiringControl = ["LOCK", "PAUSE_NET", "RESUME_NET"];

// Read current child-side acceptance
const fullControlGranted = session.controlGranted;

if (commandsRequiringControl.includes(type) && !fullControlGranted) {
  return res
    .status(400)
    .json({ message: "Remote control not granted by child yet." });
}

      // --- 3) Log command into the session ---
      session.commands.push({ type, payload, at: new Date() });
      await session.save();

      const childId = session.childId;

      // --- 4) Update live RemoteState (lock / pause flags) ---
      if (type === "LOCK") {
        await RemoteState.findOneAndUpdate(
          { childId },
          { locked: true, pauseNet: false, forceLockUntil: null },
          { upsert: true }
        );
      } else if (type === "FORCE_LOCK") {
        const minutes = Number(payload.minutes || 15);
        const until = new Date(Date.now() + minutes * 60 * 1000);
        await RemoteState.findOneAndUpdate(
          { childId },
          { locked: true, forceLockUntil: until },
          { upsert: true }
        );
      } else if (type === "UNLOCK") {
        await RemoteState.findOneAndUpdate(
          { childId },
          { locked: false, pauseNet: false, forceLockUntil: null, controlGranted: false },
          { upsert: true }
        );
      } else if (type === "PAUSE_NET") {
        await RemoteState.findOneAndUpdate(
          { childId },
          { pauseNet: true },
          { upsert: true }
        );
      } else if (type === "RESUME_NET") {
        await RemoteState.findOneAndUpdate(
          { childId },
          { pauseNet: false },
          { upsert: true }
        );
      }
      // GRANT_CONTROL / REVOKE_CONTROL do not touch RemoteState

      // --- 5) Push notification to child devices ---
      const tokens = await getChildTokens(childId);
      if (tokens.length) {
        let title = "Remote control command";
        let body = "Your parent has sent a remote command.";
        let action = "generic";

        if (type === "LOCK") {
          title = "Device locked by parent";
          body = "Your parent has locked this device.";
          action = "lock";
        } else if (type === "FORCE_LOCK") {
          const minutes = Number(payload.minutes || 15);
          title = "Device locked by parent";
          body = `Your parent has locked this device for about ${minutes} minutes.`;
          action = "force_lock";
        } else if (type === "PAUSE_NET") {
          title = "Internet paused";
          body = "Your parent has paused risky apps.";
          action = "pause_net";
        } else if (type === "GRANT_CONTROL") {
          title = "Parent requesting control";
          body ="Your parent is requesting enhanced control. Tap when you are ready.";
          action = "grant_request";
        } else if (type === "REVOKE_CONTROL") {
          title = "Remote control relaxed";
          body = "Your parent has relaxed remote control.";
          action = "revoke";
        }

        await sendPushToTokens(tokens, { title, body }, {
          type: "remote-command",
          command: type,
          action,
          sessionId: String(session._id),
          childId: String(session.childId),
          minutes: payload.minutes || 15,
        });
      }

      return res.json({ ok: true });
    } catch (e) {
      next(e);
    }
  }
);

// ---------- POST /remote/:id/child-accept ----------
// Child taps "Grant now" → confirms control for this session
r.post(
  "/:id/child-accept",
  requireAuth,
  param("id").isString().notEmpty(),
  async (req, res, next) => {
    try {
      if (!v(req, res)) return;

      const user = req.user; // logged-in child
      if (user.role !== "Child") {
        return res.status(403).json({ message: "Only child can accept control" });
      }

      const { id } = req.params;
      const session = await RemoteSession.findById(id);
      if (!session) {
        return res.status(404).json({ message: "Session not found" });
      }

      if (String(session.childId) !== String(user._id)) {
        return res.status(403).json({ message: "Not your session" });
      }

      if (session.endedAt) {
        return res.status(400).json({ message: "Session already ended" });
      }

      session.controlGranted = true;
      session.commands.push({
        type: "CHILD_ACCEPT",
        payload: {},
        at: new Date(),
      });
      await session.save();

      await RemoteState.findOneAndUpdate(
        { childId: session.childId },
        { controlGranted: true },
        { upsert: true }
      );

      return res.json({ ok: true });
    } catch (e) {
      next(e);
    }
  }
);



// ---------- POST /remote/:id/end ----------
r.post(
  "/:id/end",
  requireAuth,
  requireParent,
  param("id").isString().notEmpty(),
  async (req, res, next) => {
    try {
      if (!v(req, res)) return;

      const parent = req.user;
      const { id } = req.params;

      const session = await RemoteSession.findById(id);
      if (!session) {
        return res.status(404).json({ message: "Session not found" });
      }

      if (
        String(session.familyId || "") !== String(parent.familyId || "") ||
        String(session.parentId || "") !== String(parent._id || "")
      ) {
        return res.status(403).json({ message: "Not your session" });
      }

      if (!session.endedAt) {
        session.endedAt = new Date();
        session.controlGranted = false;
        await session.save();

        await RemoteState.findOneAndUpdate(
          { childId: session.childId },
          { locked: false, pauseNet: false, forceLockUntil: null, controlGranted: false },
          { upsert: true }
        );
      }

      const tokens = await getChildTokens(session.childId);
      if (tokens.length) {
        await sendPushToTokens(tokens, {
          title: "Remote session ended",
          body: "Your parent has ended the remote control session.",
        }, {
          type: "remote-session-ended",
          sessionId: String(session._id),
          childId: String(session.childId),
        });
      }

      res.json({ ok: true });
    } catch (e) {
      next(e);
    }
  }
);

// ---------- GET /remote/history?childId=... ----------
r.get(
  "/history",
  requireAuth,
  requireParent,
  query("childId").isString().notEmpty(),
  async (req, res, next) => {
    try {
      if (!v(req, res)) return;

      const parent = req.user;
      const { childId } = req.query;

      await assertFamilyChild(parent, childId);

      const sessions = await RemoteSession.find({
        parentId: parent._id,
        childId,
      })
        .sort({ startedAt: -1 })
        .limit(20)
        .lean();

      res.json(
        sessions.map((s) => ({
          id: String(s._id),
          startedAt: s.startedAt,
          endedAt: s.endedAt,
          commandCount: (s.commands || []).length,
        }))
      );
    } catch (e) {
      next(e);
    }
  }
);

export default r;
