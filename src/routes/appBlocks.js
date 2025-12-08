// src/routes/appBlocks.js
import { Router } from "express";
import { body, query, param, validationResult } from "express-validator";
import { requireAuth, requireParent } from "../middleware/authz.js";
import AppBlockEntry from "../models/AppBlockEntry.js";
import AppTempUnblock from "../models/AppTempUnblock.js";

const r = Router();

// Debuggable validator
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
    res.status(400).json({ errors: e.array(), got: { query: req.query, body: req.body } });
    return false;
  }
  return true;
};

async function ensureChildInFamilyOrThrow(user, childId) {
  const { default: User } = await import("../models/User.js");
  const kid = await User.findOne({ _id: childId, role: "Child" }).lean();
  if (!kid) { const e = new Error("Child not found"); e.status = 404; throw e; }
  if (String(kid.familyId || "") !== String(user.familyId || "")) {
    const e = new Error("Child not in your family"); e.status = 403; throw e;
  }
  return kid;
}

/* TEMP UNBLOCK ROUTES */

// Create / extend a temporary unblock
r.post(
  "/temp-unblock",
  requireAuth, requireParent,
  body("childId").isMongoId(),
  body("packageName").isString().trim().isLength({ min: 3, max: 200 }).matches(/^[a-zA-Z0-9_]+(\.[a-zA-Z0-9_]+)+$/),
  body("minutes").isInt({ min: 1, max: 240 }),
  async (req, res) => {
    if (!v(req, res)) return;
    await ensureChildInFamilyOrThrow(req.user, req.body.childId);

    const minutes = Number(req.body.minutes);
    const until = new Date(Date.now() + minutes * 60 * 1000);

    const doc = await AppTempUnblock.findOneAndUpdate(
      { childId: req.body.childId, packageName: req.body.packageName },
      { $set: { until, createdBy: req.user._id } },
      { new: true, upsert: true }
    );

    res.json({ ok: true, packageName: doc.packageName, until: doc.until });
  }
);

// Clear a temporary unblock (supports query OR body)
r.delete(
  "/temp-unblock",
  requireAuth, requireParent,
  // use optional() because we accept either query or body
  query("childId").optional().isMongoId(),
  query("packageName").optional().isString().trim().isLength({ min: 3, max: 200 }).matches(/^[a-zA-Z0-9_]+(\.[a-zA-Z0-9_]+)+$/),
  async (req, res, next) => {
    try {
      if (!v(req, res)) return;

      const childId = req.query.childId || req.body.childId;
      const packageName = req.query.packageName || req.body.packageName;
      if (!childId || !packageName) {
        return res.status(400).json({ message: "childId and packageName are required" });
      }

      await ensureChildInFamilyOrThrow(req.user, childId);
      const result = await AppTempUnblock.deleteOne({ childId, packageName });
      res.json({ ok: true, deleted: result.deletedCount || 0 });
    } catch (e) { next(e); }
  }
);

// List active temp unblocks
r.get(
  "/temp-unblock",
  requireAuth,
  query("childId").isMongoId(),
  async (req, res) => {
    if (!v(req, res)) return;
    const childId = req.query.childId;

    if (req.user.role === "Parent") await ensureChildInFamilyOrThrow(req.user, childId);
    else if (req.user.role === "Child" && String(req.user._id) !== String(childId)) {
      return res.status(403).json({ message: "Not allowed" });
    }

    const now = new Date();
    const rows = await AppTempUnblock.find({ childId, until: { $gt: now } }).lean();
    res.json(rows.map(r => ({ packageName: r.packageName, until: r.until })));
  }
);

/* APP BLOCK ROUTES */
// Add a blocked app
r.post(
  "/",
  requireAuth, requireParent,
  body("childId").isMongoId(),
  body("packageName")
    .isString().trim().isLength({ min: 3, max: 200 })
    .matches(/^[a-zA-Z0-9_]+(\.[a-zA-Z0-9_]+)+$/)
    .withMessage("Enter full Android package, e.g. com.google.android.youtube"),
  async (req, res) => {
    if (!v(req, res)) return;
    await ensureChildInFamilyOrThrow(req.user, req.body.childId);

    const doc = await AppBlockEntry.findOneAndUpdate(
      { childId: req.body.childId, packageName: req.body.packageName },
      {
        $setOnInsert: {
          childId: req.body.childId,
          packageName: req.body.packageName,
          source: "custom",
          createdBy: req.user._id,
        }
      },
      { new: true, upsert: true }
    );
    res.status(201).json(doc);
  }
);

// Remove a blocked app (keep AFTER temp-unblock routes)
r.delete(
  "/:id",
  requireAuth, requireParent,
  param("id").isMongoId(),
  async (req, res) => {
    if (!v(req, res)) return;
    const row = await AppBlockEntry.findById(req.params.id).lean();
    if (!row) return res.status(404).json({ message: "Not found" });
    await ensureChildInFamilyOrThrow(req.user, row.childId);
    await AppBlockEntry.deleteOne({ _id: row._id });
    res.json({ ok: true });
  }
);

// List blocked apps for a child
r.get(
  "/",
  requireAuth,
  query("childId").isMongoId(),
  async (req, res) => {
    if (!v(req, res)) return;
    const childId = req.query.childId;

    if (req.user.role === "Parent") await ensureChildInFamilyOrThrow(req.user, childId);
    else if (req.user.role === "Child" && String(req.user._id) !== String(childId)) {
      return res.status(403).json({ message: "Not allowed" });
    }

    const rows = await AppBlockEntry.find({ childId }).sort({ packageName: 1 }).lean();
    res.json(rows);
  }
);

export default r;
