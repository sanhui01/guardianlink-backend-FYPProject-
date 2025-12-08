// src/routes/rewards.js
import { Router } from "express";
import { body, query, param, validationResult } from "express-validator";
import { requireAuth, requireParent } from "../middleware/authz.js";

import RewardTask from "../models/RewardTask.js";
import RewardPointEntry from "../models/RewardPointEntry.js";
import RewardRedemption from "../models/RewardRedemption.js";
import PushToken from "../models/PushToken.js";
import TimeLimitSetting from "../models/TimeLimitSetting.js";
import { sendPushToTokens } from "../utils/push.js";

//encrypt photo
import multer from "multer";
import {
  encryptAndSaveProof,
  loadAndDecryptProof,
} from "../utils/proofCrypto.js";

const r = Router();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB max
});

/* ----------------- shared helpers ----------------- */

// Debuggable validator (same pattern as appBlocks.js)
const v = (req, res) => {
  const e = validationResult(req);
  if (!e.isEmpty()) {
    console.warn("VALIDATION 400 DEBUG:", {
      method: req.method,
      path: req.path,
      query: req.query,
      body: req.body,
      errors: e.array(),
    });
    res
      .status(400)
      .json({ errors: e.array(), got: { query: req.query, body: req.body } });
    return false;
  }
  return true;
};

async function ensureChildInFamilyOrThrow(user, childId) {
  const { default: User } = await import("../models/User.js");
  const kid = await User.findOne({ _id: childId, role: "Child" }).lean();
  if (!kid) {
    const e = new Error("Child not found");
    e.status = 404;
    throw e;
  }
  if (String(kid.familyId || "") !== String(user.familyId || "")) {
    const e = new Error("Child not in your family");
    e.status = 403;
    throw e;
  }
  return kid;
}

async function getPointBalance(childId) {
  const rows = await RewardPointEntry.find({ childId })
    .select("delta")
    .lean();
  return rows.reduce((sum, r) => sum + (r.delta || 0), 0);
}

async function awardPointsForTask(task) {
  if (!task || task.pointsAwarded || !task.points || task.points <= 0) {
    return;
  }

  await RewardPointEntry.create({
    familyId: task.familyId,
    childId: task.childId,
    taskId: task._id,
    source: "task",
    delta: task.points,
    description: task.title?.slice(0, 150) || "Task completed",
  });

  task.pointsAwarded = true;
  task.awardedAt = new Date();
  await task.save();
}

// convert payload {title, body, ...data} → notification + data (strings only)
function splitNotificationPayload(payload = {}) {
  const { title = "", body = "", ...rest } = payload;
  const data = {};
  for (const [k, v] of Object.entries(rest)) {
    if (v === undefined || v === null) continue;
    data[k] = String(v);
  }
  return { notification: { title, body }, data };
}

async function pushToParents(familyId, payload) {
  try {
    const rows = await PushToken.find({ familyId, role: "Parent" })
      .select("fcmToken")
      .lean();
    const tokens = rows.map((t) => t.fcmToken).filter(Boolean);
    if (!tokens.length) return;

    const { notification, data } = splitNotificationPayload(payload);
    await sendPushToTokens(tokens, notification, data);
  } catch (e) {
    console.warn("pushToParents failed:", e.message || e);
  }
}

async function pushToChildren(familyId, payload) {
  try {
    const rows = await PushToken.find({ familyId, role: "Child" })
      .select("fcmToken")
      .lean();
    const tokens = rows.map((t) => t.fcmToken).filter(Boolean);
    if (!tokens.length) return;

    const { notification, data } = splitNotificationPayload(payload);
    await sendPushToTokens(tokens, notification, data);
  } catch (e) {
    console.warn("pushToChildren failed:", e.message || e);
  }
}

// NEW: add extra screen-time minutes for today only (does NOT change parent limit)
async function addScreenTimeBonus(childId, bonusMinutes) {
  if (!bonusMinutes || bonusMinutes <= 0) return;

  const now = new Date();
  const endOfDay = new Date(now);
  endOfDay.setHours(23, 59, 59, 999);

  await TimeLimitSetting.findOneAndUpdate(
    { childId },
    {
      $inc: { bonusMinutes },
      $set: { bonusExpiresAt: endOfDay },
    },
    { new: true, upsert: true }
  );
}

/* ----------------- serializer ----------------- */

function serializeTask(t) {
  if (!t) return null;
  return {
    id: String(t._id),
    childId: String(t.childId),
    parentId: t.parentId ? String(t.parentId) : null,
    familyId: t.familyId ? String(t.familyId) : null,
    childName: t.childName || null, // optional, not always present
    title: t.title,
    description: t.description || "",
    category: t.category || "",
    points: t.points || 0,
    type: t.type || "default",
    autoVerify: !!t.autoVerify,
    status: t.status || "assigned",
    dueAt: t.dueAt || null,
    proofPhotoUrl: t.proofPhotoUrl || null,
    proofNote: t.proofNote || null,
    completedAt: t.completedAt || null,
    approvedAt: t.approvedAt || null,
    awardedAt: t.awardedAt || null,
    createdAt: t.createdAt,
    updatedAt: t.updatedAt,
  };
}

/* ----------------- TASK ROUTES ----------------- */

// Parent assigns task
r.post(
  "/tasks",
  requireAuth,
  requireParent,
  body("childId").isMongoId(),
  body("title").isString().trim().isLength({ min: 3, max: 120 }),
  body("description")
    .optional()
    .isString()
    .trim()
    .isLength({ min: 0, max: 2000 }),
  body("category").optional().isString().trim().isLength({ min: 1, max: 50 }),
  body("points").isInt({ min: 0, max: 100000 }),
  body("type").optional().isIn(["default", "sudden"]),
  body("autoVerify").optional().isBoolean(),
  body("dueAt").optional().isISO8601(),
  async (req, res, next) => {
    try {
      if (!v(req, res)) return;

      const kid = await ensureChildInFamilyOrThrow(req.user, req.body.childId);

      const type = req.body.type || "default";
      const autoVerify =
        typeof req.body.autoVerify === "boolean"
          ? req.body.autoVerify
          : type === "default";

      const doc = await RewardTask.create({
        familyId: kid.familyId,
        parentId: req.user._id,
        childId: kid._id,
        title: req.body.title,
        description: req.body.description || "",
        category: req.body.category || "",
        points: Number(req.body.points) || 0,
        type,
        autoVerify,
        status: "assigned",
        dueAt: req.body.dueAt ? new Date(req.body.dueAt) : undefined,
      });

      // Notify child devices (safe - internal try/catch in helper)
      await pushToChildren(kid.familyId, {
        type: "task_assigned",
        title: "New task assigned",
        body: doc.title,
        taskId: String(doc._id),
        childId: String(kid._id),
      });

      res.status(201).json(serializeTask(doc));
    } catch (e) {
      next(e);
    }
  }
);

// List tasks (Parent: family; Child: own)
r.get(
  "/tasks",
  requireAuth,
  query("childId").optional().isMongoId(),
  query("status").optional().isString().trim(),
  async (req, res, next) => {
    try {
      if (!v(req, res)) return;

      let filter = {};
      let childId = req.query.childId;

      if (req.user.role === "Child") {
        childId = String(req.user._id);
        filter.childId = childId;
      } else if (req.user.role === "Parent") {
        if (childId) {
          const kid = await ensureChildInFamilyOrThrow(req.user, childId);
          filter.childId = kid._id;
          filter.familyId = kid.familyId;
        } else {
          // all children in this family
          filter.familyId = req.user.familyId;
        }
      } else {
        return res.status(403).json({ message: "Unsupported role" });
      }

      if (req.query.status) {
        filter.status = req.query.status;
      }

      const rows = await RewardTask.find(filter)
        .sort({ createdAt: -1 })
        .lean();

      res.json(rows.map(serializeTask));
    } catch (e) {
      next(e);
    }
  }
);

// NEW: Parent can delete pending task (assigned/accepted only)
r.delete(
  "/tasks/:id",
  requireAuth,
  requireParent,
  param("id").isMongoId(),
  async (req, res, next) => {
    try {
      if (!v(req, res)) return;

      const id = req.params.id;

      const task = await RewardTask.findOne({
        _id: id,
        parentId: req.user._id,
      });
      if (!task) {
        return res.status(404).json({ error: "Task not found" });
      }

      const deletableStatuses = ["assigned", "accepted"];
      if (!deletableStatuses.includes(task.status)) {
        return res.status(400).json({
          error: "Only pending tasks (assigned/accepted) can be deleted",
        });
      }

      await task.deleteOne();

      res.json({ ok: true });
    } catch (e) {
      next(e);
    }
  }
);

// Child accepts task
r.post(
  "/tasks/:id/accept",
  requireAuth,
  param("id").isMongoId(),
  async (req, res, next) => {
    try {
      if (!v(req, res)) return;
      if (req.user.role !== "Child") {
        return res.status(403).json({ message: "Only child can accept task" });
      }

      const task = await RewardTask.findById(req.params.id);
      if (!task) return res.status(404).json({ message: "Task not found" });

      if (String(task.childId) !== String(req.user._id)) {
        return res.status(403).json({ message: "Not your task" });
      }

      if (task.status !== "assigned") {
        return res
          .status(400)
          .json({ message: `Cannot accept task in status ${task.status}` });
      }

      task.status = "accepted";
      await task.save();

      await pushToParents(task.familyId, {
        type: "task_accepted",
        title: "Task accepted",
        body: task.title,
        taskId: String(task._id),
        childId: String(task.childId),
      });

      res.json({ ok: true, status: task.status });
    } catch (e) {
      next(e);
    }
  }
);

// Child completes task
r.post(
  "/tasks/:id/complete",
  requireAuth,
  param("id").isMongoId(),
  body("proofPhotoUrl").optional().isString().trim().isLength({ max: 400 }),
  body("proofNote").optional().isString().trim().isLength({ max: 500 }),
  async (req, res, next) => {
    try {
      if (!v(req, res)) return;
      if (req.user.role !== "Child") {
        return res
          .status(403)
          .json({ message: "Only child can complete task" });
      }

      const task = await RewardTask.findById(req.params.id);
      if (!task) return res.status(404).json({ message: "Task not found" });

      if (String(task.childId) !== String(req.user._id)) {
        return res.status(403).json({ message: "Not your task" });
      }

      if (!["assigned", "accepted"].includes(task.status)) {
        return res.status(400).json({
          message: `Cannot complete task in status ${task.status}`,
        });
      }

      // keep whatever URL/path the server set when photo was uploaded.
      // Client can pass it back but we don't trust/require it.
      if (!task.proofPhotoUrl && req.body.proofPhotoUrl) {
      task.proofPhotoUrl = req.body.proofPhotoUrl;
      } 
      task.proofNote = req.body.proofNote || task.proofNote;
      task.completedAt = new Date();

      if (task.autoVerify) {
        task.status = "approved";
        task.approvedAt = new Date();
        await task.save();
        await awardPointsForTask(task);

        await pushToParents(task.familyId, {
          type: "task_auto_approved",
          title: "Task completed",
          body: task.title,
          taskId: String(task._id),
          childId: String(task.childId),
        });

        return res.json({ ok: true, status: task.status, autoVerified: true });
      } else {
        task.status = "completed"; // waiting for parent approval
        await task.save();

        await pushToParents(task.familyId, {
          type: "task_completed_pending",
          title: "Task pending approval",
          body: task.title,
          taskId: String(task._id),
          childId: String(task.childId),
        });

        return res.json({
          ok: true,
          status: task.status,
          autoVerified: false,
        });
      }
    } catch (e) {
      next(e);
    }
  }
);

// Parent approves / rejects a completed task
r.patch(
  "/tasks/:id/verify",
  requireAuth,
  requireParent,
  param("id").isMongoId(),
  body("approve").isBoolean(),
  body("rejectReason")
    .optional()
    .isString()
    .trim()
    .isLength({ min: 0, max: 300 }),
  async (req, res, next) => {
    try {
      if (!v(req, res)) return;

      const task = await RewardTask.findById(req.params.id);
      if (!task) return res.status(404).json({ message: "Task not found" });

      // ensure child really belongs to parent
      await ensureChildInFamilyOrThrow(req.user, task.childId);

      if (task.status !== "completed") {
        return res.status(400).json({
          message: `Task not in 'completed' status (current: ${task.status})`,
        });
      }

      const approve = !!req.body.approve;

      if (approve) {
        task.status = "approved";
        task.approvedAt = new Date();
        await task.save();
        await awardPointsForTask(task);

        await pushToChildren(task.familyId, {
          type: "task_approved",
          title: "Task approved 🎉",
          body: `${task.title} (+${task.points} pts)`,
          taskId: String(task._id),
          childId: String(task.childId),
        });

        res.json({ ok: true, status: task.status, points: task.points });
      } else {
        task.status = "rejected";
        await task.save();

        await pushToChildren(task.familyId, {
          type: "task_rejected",
          title: "Task rejected",
          body: req.body.rejectReason || task.title,
          taskId: String(task._id),
          childId: String(task.childId),
        });

        res.json({ ok: true, status: task.status });
      }
    } catch (e) {
      next(e);
    }
  }
);

/* ----------------- POINTS & HISTORY ----------------- */

// Get points + history
r.get(
  "/points",
  requireAuth,
  query("childId").optional().isMongoId(),
  async (req, res, next) => {
    try {
      if (!v(req, res)) return;

      let childId = req.query.childId;

      if (req.user.role === "Child") {
        childId = String(req.user._id);
      } else if (req.user.role === "Parent") {
        if (!childId) {
          return res
            .status(400)
            .json({ message: "childId is required for parent view" });
        }
        await ensureChildInFamilyOrThrow(req.user, childId);
      } else {
        return res.status(403).json({ message: "Unsupported role" });
      }

      const entries = await RewardPointEntry.find({ childId })
        .sort({ createdAt: -1 })
        .limit(200)
        .lean();

      const balance = entries.reduce((sum, e) => sum + (e.delta || 0), 0);

      res.json({
        childId,
        balance,
        history: entries.map((e) => ({
          id: e._id,
          source: e.source,
          delta: e.delta,
          description: e.description,
          taskId: e.taskId,
          createdAt: e.createdAt,
        })),
      });
    } catch (e) {
      next(e);
    }
  }
);

/* ----------------- REDEMPTION ----------------- */

// Redeem reward points
r.post(
  "/redeem",
  requireAuth,
  body("childId").optional().isMongoId(),
  body("label").isString().trim().isLength({ min: 3, max: 120 }),
  body("costPoints").isInt({ min: 1, max: 100000 }),
  // allow "custom_big" for 50-pt big rewards
  body("rewardType").isIn(["screen_time", "app_unlock", "custom", "custom_big"]),
  body("bonusMinutes").optional().isInt({ min: 1, max: 600 }),
  body("packageName")
    .optional()
    .isString()
    .trim()
    .isLength({ min: 3, max: 200 }),
  body("note").optional().isString().trim().isLength({ min: 0, max: 300 }),
  async (req, res, next) => {
    try {
      if (!v(req, res)) return;

      const costPoints = Number(req.body.costPoints);
      let childId = req.body.childId;
      let familyId;

      if (req.user.role === "Child") {
        childId = String(req.user._id);
        familyId = req.user.familyId;
      } else if (req.user.role === "Parent") {
        if (!childId) {
          return res
            .status(400)
            .json({ message: "childId is required for parent redemption" });
        }
        const kid = await ensureChildInFamilyOrThrow(req.user, childId);
        familyId = kid.familyId;
      } else {
        return res.status(403).json({ message: "Unsupported role" });
      }

      const balance = await getPointBalance(childId);
      if (balance < costPoints) {
        return res.status(400).json({
          message: "Not enough points",
          balance,
          required: costPoints,
        });
      }

      const rewardType = req.body.rewardType;

      const payload = {
        bonusMinutes:
          rewardType === "screen_time"
            ? Number(req.body.bonusMinutes || 0)
            : undefined,
        // we no longer auto-unlock apps; packageName is stored just for reference
        packageName:
          rewardType === "app_unlock"
            ? req.body.packageName || undefined
            : undefined,
        note: req.body.note || undefined,
      };

      const redemption = await RewardRedemption.create({
        familyId,
        childId,
        requestedBy: req.user._id,
        rewardType,
        label: req.body.label,
        costPoints,
        payload,
      });

      await RewardPointEntry.create({
        familyId,
        childId,
        source: "redeem",
        delta: -costPoints,
        description: redemption.label,
      });

      // Apply concrete effects only for screen-time bonus
      if (rewardType === "screen_time" && payload.bonusMinutes) {
        await addScreenTimeBonus(childId, payload.bonusMinutes);
      }

      // Push notification
      if (req.user.role === "Child") {
        await pushToParents(familyId, {
          type: "reward_redeemed",
          title: "Reward redeemed",
          body: `${req.user.displayName || "Child"} redeemed: ${
            redemption.label
          }`,
          childId,
          redemptionId: String(redemption._id),
        });
      } else if (req.user.role === "Parent") {
        await pushToChildren(familyId, {
          type: "reward_redeemed_parent",
          title: "Reward granted",
          body: redemption.label,
          childId,
          redemptionId: String(redemption._id),
        });
      }

      // For "custom" / "custom_big" / "app_unlock", the actual *reward*
      // is decided and applied by the parent (manual, safer for InfoSec).

      res.status(201).json({
        ok: true,
        redemption: {
          id: redemption._id,
          rewardType: redemption.rewardType,
          label: redemption.label,
          costPoints: redemption.costPoints,
          payload: redemption.payload,
          createdAt: redemption.createdAt,
        },
      });
    } catch (e) {
      next(e);
    }
  }
);

// View redemption history
r.get(
  "/redemptions",
  requireAuth,
  query("childId").optional().isMongoId(),
  async (req, res, next) => {
    try {
      if (!v(req, res)) return;

      let childId = req.query.childId;
      let familyId = req.user.familyId;

      if (req.user.role === "Child") {
        childId = String(req.user._id);
      } else if (req.user.role === "Parent") {
        if (!childId) {
          return res
            .status(400)
            .json({ message: "childId is required for parent view" });
        }
        const kid = await ensureChildInFamilyOrThrow(req.user, childId);
        familyId = kid.familyId;
      } else {
        return res.status(403).json({ message: "Unsupported role" });
      }

      const rows = await RewardRedemption.find({ childId, familyId })
        .sort({ createdAt: -1 })
        .limit(200)
        .lean();

      res.json(
        rows.map((rrow) => ({
          id: rrow._id,
          childId: rrow.childId,
          requestedBy: rrow.requestedBy,
          rewardType: rrow.rewardType,
          label: rrow.label,
          costPoints: rrow.costPoints,
          payload: rrow.payload,
          createdAt: rrow.createdAt,
        }))
      );
    } catch (e) {
      next(e);
    }
  }
);

// ---------------------------------------------------------------------------
// Upload proof photo for a task (Child)
// POST /rewards/tasks/:id/proof-photo
// form-data: file: <image/*>
// ---------------------------------------------------------------------------
r.post(
  "/tasks/:id/proof-photo",
  requireAuth,
  param("id").isMongoId(),
  upload.single("file"),
  async (req, res, next) => {
    try {
      if (!v(req, res)) return;

      if (req.user.role !== "Child") {
        return res.status(403).json({ message: "Only child can upload proof" });
      }

      const taskId = req.params.id;
      const task = await RewardTask.findById(taskId);
      if (!task) return res.status(404).json({ message: "Task not found" });

      // Child can only upload for their own task
      if (String(task.childId) !== String(req.user._id)) {
        return res.status(403).json({ message: "Not your task" });
      }

      if (!req.file || !req.file.buffer) {
        return res.status(400).json({ message: "No file uploaded" });
      }

      // Encrypt and save
      encryptAndSaveProof(taskId, req.file.buffer);

      // Store a logical URL in DB so UI can know "this task has photo"
      // (actual file path is derived from taskId; nothing public here)
      task.proofPhotoUrl =
        task.proofPhotoUrl ||
        `/rewards/tasks/${taskId}/proof-photo`; // safe internal API path
      await task.save();

      return res.json({
        url: `/rewards/tasks/${taskId}/proof-photo`,
      });
    } catch (e) {
      console.error("❌ proof-photo upload error:", e);
      next(e);
    }
  }
);

// ---------------------------------------------------------------------------
// View proof photo (Parent or owning Child)
// GET /rewards/tasks/:id/proof-photo
// Streams decrypted image bytes
// ---------------------------------------------------------------------------
r.get(
  "/tasks/:id/proof-photo",
  requireAuth,
  param("id").isMongoId(),
  async (req, res, next) => {
    try {
      if (!v(req, res)) return;

      const taskId = req.params.id;
      const task = await RewardTask.findById(taskId);
      if (!task) return res.status(404).json({ message: "Task not found" });

      const isChild = req.user.role === "Child";
      const isParent = req.user.role === "Parent" || req.user.role === "Superuser";

      if (isChild) {
        // Child can only view their own proof
        if (String(task.childId) !== String(req.user._id)) {
          return res.status(403).json({ message: "Not your task" });
        }
      } else if (isParent) {
        // Parent must belong to same family as child
        await ensureChildInFamilyOrThrow(req.user, task.childId);
      } else {
        return res.status(403).json({ message: "Unsupported role" });
      }

      let imageBuffer;
      try {
        imageBuffer = loadAndDecryptProof(taskId);
      } catch (e) {
        if (e.code === "ENOENT") {
          return res.status(404).json({ message: "Proof photo not found" });
        }
        console.error("❌ loadAndDecryptProof failed:", e);
        return res.status(500).json({ message: "Failed to load proof photo" });
      }

      // We don't know if it's JPEG/PNG/etc; most phones send jpeg.
      // You can inspect magic bytes if you want. For now, default to image/jpeg.
      res.setHeader("Content-Type", "image/jpeg");
      res.send(imageBuffer);
    } catch (e) {
      next(e);
    }
  }
);


export default r;
