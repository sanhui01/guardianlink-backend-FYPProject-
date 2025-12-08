// src/routes/appInventory.js
import { Router } from "express";
import { body, query, validationResult } from "express-validator";
import { requireAuth } from "../middleware/authz.js";
import AppInventoryEntry from "../models/AppInventoryEntry.js";

const r = Router();

/**
 * Helper that validate request and return false if invalid
 */
const v = (req, res) => {
  const e = validationResult(req);
  if (!e.isEmpty()) {
    res.status(400).json({ errors: e.array() });
    return false;
  }
  return true;
};

/**
 * Is a helper to ensure the child belongs to the parent's family
 */
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

/**
 * POST /inventory/apps
 * Child uploads installed apps to the backend once they logged in the apps.
 */
r.post(
  "/apps",
  requireAuth,

  // apps must be an array
  body("apps").isArray({ min: 1, max: 5000 }),

  //   NEW: allow ANY non-empty string 
  body("apps.*.packageName").isString().trim().isLength({ min: 1, max: 200 }),

  body("apps.*.appLabel").optional().isString().trim(),
  body("apps.*.versionName").optional().isString().trim(),
  body("apps.*.versionCode").optional().isString().trim(),
  body("apps.*.systemApp").optional().isBoolean(),

  async (req, res) => {
    if (!v(req, res)) return;

    // Only Child role can upload inventory
    if (req.user.role !== "Child") {
      return res
        .status(403)
        .json({ message: "Only child devices may upload inventory" });
    }

    try {
      const childId = req.user._id;
      const apps = req.body.apps || [];
      const now = new Date();

      if (apps.length > 0) {
        // Bulk upsert for performance
        const bulk = AppInventoryEntry.collection.initializeUnorderedBulkOp();

        for (const a of apps) {
          bulk
            .find({ childId, packageName: a.packageName })
            .upsert()
            .updateOne({
              $set: {
                childId,
                packageName: a.packageName,
                appLabel: a.appLabel || "",
                versionName: a.versionName || "",
                versionCode: a.versionCode || "",
                systemApp: !!a.systemApp,
                lastSeenAt: now,
              },
            });
        }

        await bulk.execute();
      }

      return res.status(201).json({
        ok: true,
        upserts: apps.length,
      });
    } catch (e) {
      const code = e.status || 500;
      return res.status(code).json({ message: e.message || "Server error" });
    }
  }
);

/**
 * GET /inventory/apps?childId=...
 * Parent fetches child's apps; child fetches own list.
 */
r.get(
  "/apps",
  requireAuth,

  query("childId").optional().isMongoId(),

  async (req, res) => {
    if (!v(req, res)) return;

    try {
      let childId;

      // Child can fetch own data
      if (req.user.role === "Child") {
        childId = req.user._id;
      } else {
        // Parent must provide childId
        childId = req.query.childId;
        if (!childId) {
          return res
            .status(400)
            .json({ message: "childId is required for parent" });
        }
        await ensureChildInFamilyOrThrow(req.user, childId);
      }

      // Fetch inventory
      const items = await AppInventoryEntry.find({ childId })
        .sort({ systemApp: 1, appLabel: 1, packageName: 1 })
        .lean();

      return res.json(
        items.map((i) => ({
          id: String(i._id),
          packageName: i.packageName,
          appLabel: i.appLabel || i.packageName,
          systemApp: !!i.systemApp,
        }))
      );
    } catch (e) {
      const code = e.status || 500;
      return res
        .status(code)
        .json({ message: e.message || "Server error fetching inventory" });
    }
  }
);

export default r;
