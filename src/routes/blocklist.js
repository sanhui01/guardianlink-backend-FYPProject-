// src/routes/blocklist.js
import { Router } from "express";
import rateLimit from "express-rate-limit";
import { body, query, param, validationResult } from "express-validator";
import BlockEntry, { normalizeUrl } from "../models/BlockEntry.js";
import { requireAuth, requireParent } from "../middleware/authz.js";

const r = Router();

// local limiter
const limiter = rateLimit({ windowMs: 60_000, max: 60, standardHeaders: true, legacyHeaders: false });
r.use(limiter);

// helper throw 400 error status
function handleValidation(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
}

// helper that ensure the child belongs to the same family as the parent
async function ensureChildInFamilyOrThrow(parentUser, childId) {
  const { default: User } = await import("../models/User.js");
  const kid = await User.findOne({ _id: childId, role: "Child" }).lean();
  if (!kid) {
    const e = new Error("Child not found");
    e.status = 404; throw e;
  }
  if (String(kid.familyId || "") !== String(parentUser.familyId || "")) {
    const e = new Error("Child not in your family");
    e.status = 403; throw e;
  }
  return kid;
}

/**
 * POST /blocklist
 * Parent adds a single URL to a child's custom blocklist.
 * Body: { childId, url }
 */
r.post("/",
  requireAuth, requireParent,
  body("childId").isMongoId(),
  body("url").isString().trim().isLength({ min: 1, max: 1024 }),
  async (req, res, next) => {
    try {
      handleValidation(req, res);

      await ensureChildInFamilyOrThrow(req.user, req.body.childId);

      let parsed;
      try {
        parsed = normalizeUrl(req.body.url);
      } catch (e) {
        return res.status(400).json({ message: e.message || "Invalid URL" });
      }

      const doc = await BlockEntry.findOneAndUpdate(
        { childId: req.body.childId, urlHash: parsed.urlHash },
        {
          $setOnInsert: {
            childId: req.body.childId,
            urlOriginal: req.body.url.trim(),
            urlNormalized: parsed.normalized,
            host: parsed.host,
            path: parsed.path,
            urlHash: parsed.urlHash,
            source: "custom",
            createdBy: req.user._id,
          }
        },
        { new: true, upsert: true }
      );

      res.status(201).json(doc);
    } catch (e) { next(e); }
  }
);

/**
 * POST /blocklist/bulk
 * Body: { childId, urls: [ ... ] }
 */
r.post("/bulk",
  requireAuth, requireParent,
  body("childId").isMongoId(),
  body("urls").isArray({ min: 1, max: 200 }),
  async (req, res, next) => {
    try {
      handleValidation(req, res);

      await ensureChildInFamilyOrThrow(req.user, req.body.childId);

      const results = [];
      for (const raw of req.body.urls) {
        try {
          const { normalized, host, path, urlHash } = normalizeUrl(String(raw || ""));
          const doc = await BlockEntry.findOneAndUpdate(
            { childId: req.body.childId, urlHash },
            {
              $setOnInsert: {
                childId: req.body.childId,
                urlOriginal: String(raw || "").trim(),
                urlNormalized: normalized,
                host, path, urlHash,
                source: "custom",
                createdBy: req.user._id,
              }
            },
            { new: true, upsert: true }
          );
          results.push({ ok: true, id: doc._id, url: doc.urlOriginal });
        } catch (err) {
          results.push({ ok: false, error: err.message || "Invalid URL", url: String(raw || "") });
        }
      }
      res.json({ results });
    } catch (e) { next(e); }
  }
);

/**
 * GET /blocklist?childId=...
 * Parent: view a child's list
 * Child: may view own
 */
r.get("/",
  requireAuth,
  query("childId").isMongoId(),
  async (req, res, next) => {
    try {
      handleValidation(req, res);

      const childId = req.query.childId;

      if (req.user.role === "Parent") {
        await ensureChildInFamilyOrThrow(req.user, childId);
      } else if (req.user.role === "Child") {
        if (String(req.user._id) !== String(childId)) {
          return res.status(403).json({ message: "Not allowed" });
        }
      }

      const list = await BlockEntry.find({ childId }).sort({ createdAt: -1 }).lean();
      res.json(list);
    } catch (e) { next(e); }
  }
);

/**
 * DELETE /blocklist/:id
 * Parent removes an entry from a child's list.
 */
r.delete("/:id",
  requireAuth, requireParent,
  param("id").isMongoId(),
  async (req, res, next) => {
    try {
      handleValidation(req, res);

      // Load entry to check family membership
      const entry = await BlockEntry.findById(req.params.id).lean();
      if (!entry) return res.status(404).json({ message: "Not found" });

      await ensureChildInFamilyOrThrow(req.user, entry.childId);

      await BlockEntry.deleteOne({ _id: entry._id });
      res.json({ ok: true });
    } catch (e) { next(e); }
  }
);

export default r;
