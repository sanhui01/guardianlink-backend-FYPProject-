// src/routes/activity.js

import { Router } from "express";
import { body, query, validationResult } from "express-validator";
import { requireAuth } from "../middleware/authz.js";
import BlockedAttempt from "../models/BlockedAttempt.js";
import KeywordSetting from "../models/KeywordSetting.js";
import HistoryEntry from "../models/HistoryEntry.js";
import KeywordEntry from "../models/KeywordEntry.js";
import BlockEntry from "../models/BlockEntry.js";
import SearchQueryEntry from "../models/SearchQueryEntry.js";
import PushToken from "../models/PushToken.js";
import User from "../models/User.js";
import { sendPushToTokens } from "../utils/push.js";

import dayjs from "dayjs";
import utc from "dayjs/plugin/utc.js";
import timezone from "dayjs/plugin/timezone.js";

// Enable UTC + timezone features on dayjs
dayjs.extend(utc);
dayjs.extend(timezone);

// Create a new router for /activity related endpoints
const r = Router();

// ---------- small helper for validator ----------
// This function checks if express-validator found any errors.
// If errors exist, it sends 400 response and returns false.
// If no errors, returns true so the handler can continue.
const v = (req, res) => {
  const e = validationResult(req);
  if (!e.isEmpty()) {
    res.status(400).json({ errors: e.array() });
    return false;
  }
  return true;
};

// This tries multiple places to figure out which child the request is about.
function getChildIdFromReq(req) {
  const user = req.user || {};
  const fromBody = req.body?.childId;
  const fromQuery = req.query?.childId;

  // If childId is explicitly sent in body or query, use that first
  if (fromBody) return fromBody;
  if (fromQuery) return fromQuery;

  // If the auth middleware already attached a childId directly on req.user
  if (user.childId) return user.childId;

  // If token belongs to a child device: use user's _id or sub
  if (user.role === "Child") {
    if (user._id) return user._id;
    if (user.sub) return user.sub; // fallback if your auth uses "sub"
  }

  // If token belongs to a parent and you have concept of currentChildId in token
  if (user.role === "Parent" && user.currentChildId) return user.currentChildId;

  // If nothing worked, return null so caller can handle error
  return null;
}

// Simple URL normaliser.
// - Tries to ensure we have a proper URL.
// - Returns an object { url, host, path } or null if invalid.
function parseUrl(raw) {
  if (!raw) return null;
  let str = String(raw).trim();
  if (!/^https?:\/\//i.test(str)) {
    // If no protocol, assume https
    str = "https://" + str;
  }
  try {
    const u = new URL(str);
    return {
      url: u.toString(),
      host: u.hostname,
      path: u.pathname || "/",
    };
  } catch {
    // If URL is malformed, return null
    return null;
  }
}

// Try to guess the search text from a known search-engine URL
function extractSearchQueryFromUrl(urlStr) {
  if (!urlStr) return "";
  try {
    const u = new URL(urlStr);
    // Google web search
    if (u.hostname.includes("google.") && u.pathname === "/search") {
      return u.searchParams.get("q") || "";
    }
    // YouTube
    if (u.hostname.includes("youtube.com") && u.pathname === "/results") {
      return u.searchParams.get("search_query") || "";
    }
    // Bing
    if (u.hostname.includes("bing.com")) {
      return u.searchParams.get("q") || "";
    }
    // Yahoo
    if (u.hostname.includes("search.yahoo.")) {
      return u.searchParams.get("p") || "";
    }
    return "";
  } catch {
    return "";
  }
}

// Very simple engine detector for display
function detectEngineFromUrl(urlStr) {
  if (!urlStr) return "unknown";
  try {
    const u = new URL(urlStr);
    const h = u.hostname;
    if (h.includes("google.")) return "google";
    if (h.includes("youtube.com")) return "youtube";
    if (h.includes("bing.com")) return "bing";
    if (h.includes("search.yahoo.")) return "yahoo";
    return "unknown";
  } catch {
    return "unknown";
  }
}


/**
 * CHILD posts when a page / app is blocked (fire-and-forget).
 * We accept: url, host/domain, keyword search and during bedtime
 */
r.post(
  "/blocked",
  requireAuth, // make sure user is authenticated
  // allow empty strings / missing values; we'll normalise in handler
  body("url").optional({ nullable: true }).isString(),
  body("host").optional({ nullable: true }).isString(),
  body("path").optional({ nullable: true }).isString(),
  body("appPackage").optional().isString(),
  body("matchedRule").optional().isString(),
  body("childId").optional().isString(), // Parent may simulate for testing
  async (req, res, next) => {
    try {
      // Run input validation helper
      if (!v(req, res)) return;

      // ----- who is this for? -----
      // Decide which childId this blocked event belongs to
      let childId = req.body.childId;
      if (req.user.role === "Child") {
        // If the caller is a real child device, force childId = that user
        childId = req.user._id;
      }
      if (!childId) {
        // If still no childId, reject request
        return res.status(400).json({ message: "childId missing" });
      }

      // ----- normalise url / host / path -----
      let { url, host, path } = req.body;

      // Treat empty strings as "not provided"
      if (typeof url === "string" && url.trim() === "") url = undefined;
      if (typeof host === "string" && host.trim() === "") host = undefined;
      if (typeof path === "string" && path.trim() === "") path = undefined;

      // If we got a URL but no host/path, try to parse URL to fill them in
      if (url && (!host || !path)) {
        try {
          const hasProtocol = /^https?:\/\//i.test(url);
          const u = new URL(hasProtocol ? url : `https://${url}`);
          host = host || u.host;
          path = path || (u.pathname || "/");
          url = u.toString();
        } catch {
          // If URL parsing fails, continue and use fallbacks below
        }
      }

      // Fallbacks so we ALWAYS store something, even for pseudo-events.
      if (!host) host = "unknown";
      if (!path) path = "/";
      if (!url) url = `https://${host}${path}`;

      // Default appPackage if not provided (assume Chrome)
      const appPackage = req.body.appPackage || "com.android.chrome";
      // matchedRule can describe which rule caused the block (optional)
      const matchedRule = req.body.matchedRule || "";

      // ----- write to Mongo -----
      // Create a new BlockedAttempt document with all the normalised fields
      const doc = await BlockedAttempt.create({
        childId,
        sourceType: "web",
        url,
        host,
        path,
        appPackage,
        matchedRule,
      });

      // ----- fire-and-forget push for KEYWORD events -----
      // This is an async IIFE: we don't wait for it to finish before responding.
      (async () => {
        try {
          // Either host is literally "keyword" or matchedRule text contains "keyword".
          const isKeywordEvent =
            host === "keyword" ||
            matchedRule.toLowerCase().includes("keyword");

          if (!isKeywordEvent) return;

          // Try to get a nice search text for the parent:
          // 1) explicit query from body (if Android sends it in future)
          // 2) parsed from the URL (google/youtube/bing/yahoo)
          // 3) fall back to matchedRule
          const queryText =
            (req.body.query && String(req.body.query)) ||
            extractSearchQueryFromUrl(url) ||
            matchedRule ||
            "Blocked keyword";

          const engine = detectEngineFromUrl(url);

          await SearchQueryEntry.create({
            childId,
            query: queryText,
            url: url || "",
            engine,
            appPackage,
            isUnsafe: true,
            reason: "blocked keyword",
            searchedAt: new Date(),
          });

          // Is alert enabled for this child?
          const setting = await KeywordSetting.findOne({ childId }).lean();
          if (!setting?.alertsEnabled) return;

          // Find the child + family info
          const child = await User.findById(childId)
            .select("displayName familyId")
            .lean();
          if (!child?.familyId) return;

          // Find all parents in the same family
          const parents = await User.find({
            familyId: child.familyId,
            role: "Parent",
          })
            .select("_id")
            .lean();

          if (!parents.length) return;

          const parentIds = parents.map((p) => p._id);

          // Fetch all distinct FCM tokens for those parents
          const tokens = await PushToken.find({
            userId: { $in: parentIds },
          }).distinct("fcmToken");

          if (!tokens.length) return;

          const childName = child.displayName || "your child";

          // Send push notification to those tokens
          await sendPushToTokens(
            tokens,
            {
              title: "Keyword Alert",
              body: `Detected blocked keyword from ${childName}.`,
            },
            {
              // Extra data payload
              type: "keyword-blocked",
              childId: String(childId),
              blockedId: String(doc._id),
              appPackage,
            }
          );
        } catch (e) {
          console.error("keyword push error:", e);
        }
      })();

      // ----- HTTP response -----
      // Reply to the caller that everything is okay
      return res.json({ ok: true });
    } catch (e) {
      // If anything unexpected happens, pass to Express error handler
      next(e);
    }
  }
);

/** PARENT (or child self) fetch list of blocked attempts */
r.get(
  "/blocked",
  requireAuth,
  // Require childId in query and ensure it looks like a Mongo ObjectId
  query("childId").isMongoId(),
  // Optional limit param to control how many records to return
  query("limit").optional().isInt({ min: 1, max: 200 }),
  async (req, res, next) => {
    try {
      // Run input validation helper
      if (!v(req, res)) return;
      // Maximum number of results to return (default: 100)
      const limit = Number(req.query.limit || 100);
      // A child user can ONLY view their own blocked attempts.
      if (
        req.user.role === "Child" &&
        String(req.user._id) !== String(req.query.childId)
      ) {
        return res.status(403).json({ message: "Not allowed" });
      }
      // Verify the childId belongs to the same family as the parent
      if (req.user.role === "Parent") {
        const kid = await User.findOne({ // Load the child
          _id: req.query.childId,
          role: "Child",
        }).lean();
        if (!kid) return res.status(404).json({ message: "Child not found" });
        // Check if child is in the same family
        if (String(kid.familyId || "") !== String(req.user.familyId || "")) {
          return res.status(403).json({ message: "Child not in your family" });
        }
      }
      // Fetch blocked attempts for the requested child
      const rows = await BlockedAttempt.find({ childId: req.query.childId })
        .sort({ blockedAt: -1 }) // newest first
        .limit(limit)
        .lean();

      const tz = "Asia/Kuala_Lumpur"; // Force Malaysia timezone
      
      // Format each entry before sending back to frontend
      const formatted = rows.map((r) => ({
        id: String(r._id),
        url: r.url,
        host: r.host,
        path: r.path,
        appPackage: r.appPackage || "",
        matchedRule: r.matchedRule || "",
        blockedAt: dayjs(r.blockedAt)
          .tz(tz)
          .format("YYYY-MM-DD HH:mm:ss"),
      }));

      return res.json(formatted);
    } catch (e) {
      next(e);
    }
  }
);

// POST /activity/history
// Logs allowed (or unsafe-but-not-blocked) browser visits
r.post(
  "/history",
  requireAuth,
  [
    // url is required and must be a non-empty string
    body("url").isString().notEmpty(),
    // title, appPackage, sourceType are optional strings
    body("title").optional().isString(),
    body("appPackage").optional().isString(),
    body("sourceType").optional().isString(),
  ],
  async (req, res, next) => {
    try {
      // Validate request input
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }
      // Determine childId from auth token or selected context
      const childId = getChildIdFromReq(req);
      if (!childId) {
        return res.status(400).json({ error: "childId could not be resolved" });
      }
      const { url, title, appPackage, sourceType = "browser" } = req.body;
      // Try to parse + normalize the URL 
      const parsed = parseUrl(url);
      if (!parsed) {
        return res.status(400).json({ error: "Invalid url" });
      }
      // -------- simple unsafe check using KeywordEntry --------
      let isUnsafe = false;
      let reason = "";

      try {
        // Load all blocked keywords for this child
        const keywords = await KeywordEntry.find({ childId }).lean();
        if (keywords && keywords.length > 0) {
          // Combine URL + title into lower-case string for matching
          const haystack = `${url} ${title || ""}`.toLowerCase();
          // Loop through each keyword
          for (const kw of keywords) {
            const phrase = (
              kw.keyword ||
              kw.phrase ||
              ""
            ).toLowerCase();
            // If keyword exists and matches any part of the haystack
            if (phrase && haystack.includes(phrase)) {
              isUnsafe = true;
              reason = `keyword: ${phrase}`;
              break;
            }
          }
        }
      } catch (e) {
        // Don't break logging if keyword check fails
        console.error("Keyword check failed in /activity/history:", e);
      }

      // extra unsafe check: URL matches website blocklist
      try {
        const parsedHost = parsed.host;      // from parseUrl(url)
        const parsedPath = parsed.path || "/";
        // Find a matching blocked website entry
        const blocked = await BlockEntry.findOne({
          childId,
          host: parsedHost,
        }).lean();

        if (blocked) {
          isUnsafe = true;
          if (!reason) reason = "blocked website";
        }
      } catch (e) {
        console.error("Website check failed in /activity/history:", e);
      }

      // Create a new history record in Mongo
      const entry = await HistoryEntry.create({
        childId,
        url: parsed.url,
        host: parsed.host,
        path: parsed.path,
        title: title || "",
        appPackage: appPackage || "",
        sourceType: sourceType || "browser",
        isUnsafe,
        reason,
        visitedAt: new Date(), // timestamp of the visit
      });

      // Return basic success info
      return res.status(201).json({
        ok: true,
        id: entry._id,
      });
    } catch (err) {
      next(err);
    }
  }
);

// GET /activity/history
// Query params:
//   childId (optional, can be resolved from token)
//   date   (YYYY-MM-DD, optional, default = today in Asia/Kuala_Lumpur)
//   filter = all | safe | unsafe (optional, default = all)
r.get(
  "/history",
  requireAuth,
  [
    query("childId").optional().isString(),
    query("date").optional().isString(),
    query("filter").optional().isIn(["all", "safe", "unsafe"]),
  ],
  async (req, res, next) => {
    try {
      // Validate query parameters
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      // Resolve childId from query or token
      const childId = getChildIdFromReq(req);
      if (!childId) {
        return res.status(400).json({ error: "childId could not be resolved" });
      }

      // Fix timezone
      const tz = "Asia/Kuala_Lumpur";
      const dateStr = req.query.date;
      let start;
      let end;

      if (dateStr) {
        // If client provided a specific date, parse it using KL timezone
        const d = dayjs.tz(dateStr, tz);
        // Reject invalid date formats
        if (!d.isValid()) {
          return res.status(400).json({ error: "Invalid date" });
        }
        start = d.startOf("day");
        end = d.endOf("day");
      } else {
        // No date given → default to "today" in KL timezone
        const now = dayjs().tz(tz);
        start = now.startOf("day");
        end = now.endOf("day");
      }

      const filter = req.query.filter || "all"; // Filter: all | safe | unsafe

      // Build Mongo query for history entries inside the day range
      const queryObj = {
        childId,
        visitedAt: {
          $gte: start.toDate(),
          $lte: end.toDate(),
        },
      };

      // If caller wants ONLY safe entries
      if (filter === "safe") {
        queryObj.isUnsafe = false;
      } else if (filter === "unsafe") {
        // If caller wants ONLY unsafe entries
        queryObj.isUnsafe = true;
      }

      // Fetch matching history entries
      const docs = await HistoryEntry.find(queryObj)
        .sort({ visitedAt: -1 }) // newest first
        .lean();

      // Shape the response in a simple format for UI
      const result = docs.map((doc) => ({
        id: String(doc._id),
        url: doc.url,
        title: doc.title || "",
        visitedAt: dayjs(doc.visitedAt).tz("Asia/Kuala_Lumpur").format(),
        isUnsafe: !!doc.isUnsafe,
        reason: doc.reason || "",
        sourceType: doc.sourceType || "browser",
        appPackage: doc.appPackage || "",
      }));

      return res.json(result);
    } catch (err) {
      next(err);
    }
  }
);

// POST /activity/search
// Logs search queries (what child typed in Google/Bing/YouTube etc)
r.post(
  "/search",
  requireAuth,
  [
    // query text is required
    body("query").isString().notEmpty(),
    // url, engine, appPackage are optional
    body("url").optional().isString(),
    body("engine").optional().isString(),
    body("appPackage").optional().isString(),
  ],
  async (req, res, next) => {
    try {
      // Validate incoming request body using express-validator
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }
      // Determine which child this search log belongs to
      const childId = getChildIdFromReq(req);
      if (!childId) {
        return res.status(400).json({ error: "childId could not be resolved" });
      }
      const { query: q, url, engine = "unknown", appPackage = "" } = req.body;

      // Prepare variables for unsafe detection
      let isUnsafe = false;
      let reason = "";

      try {
        // Load all keywords blocked for this child
        const keywords = await KeywordEntry.find({ childId }).lean();
        if (keywords && keywords.length > 0) {
          const lower = q.toLowerCase();
          for (const kw of keywords) {
            const phrase = (kw.keyword || kw.phrase || "").toLowerCase();
            // If search text contains any blocked keyword mark unsafe
            if (phrase && lower.includes(phrase)) {
              isUnsafe = true;
              reason = `keyword: ${phrase}`;
              break;
            }
          }
        }
      } catch (e) {
        console.error("Keyword check failed in /activity/search:", e);
      }

      // Save search query in Mongo
      await SearchQueryEntry.create({
        childId,
        query: q,
        url: url || "",
        engine,
        appPackage,
        isUnsafe,
        reason,
        searchedAt: new Date(), // timestamp when search happened
      });

      // Respond with success flag
      return res.json({ ok: true });
    } catch (err) {
      next(err);
    }
  }
);

// GET /activity/search
// childId (optional), date (YYYY-MM-DD, optional), filter=all|safe|unsafe
r.get(
  "/search",
  requireAuth,
  [
    query("childId").optional().isString(),
    query("date").optional().isString(),
    query("filter").optional().isIn(["all", "safe", "unsafe"]),
  ],
  async (req, res, next) => {
    try {
      // Validate query parameters
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      // Resolve childId from token or query
      const childId = getChildIdFromReq(req);
      if (!childId) {
        return res.status(400).json({ error: "childId could not be resolved" });
      }

      const tz = "Asia/Kuala_Lumpur";
      const dateStr = req.query.date;
      let start;
      let end;

      if (dateStr) {
        // If user provided ?date=YYYY-MM-DD → parse that date in Malaysia timezone
        const d = dayjs.tz(dateStr, tz);
        if (!d.isValid()) { // Reject invalid or unreadable date strings
          return res.status(400).json({ error: "Invalid date" });
        }
        // Start and end of that specific day
        start = d.startOf("day");
        end = d.endOf("day");
      } else {
        // No date provided then use today's date in Malaysia timezone
        const now = dayjs().tz(tz);
        start = now.startOf("day");
        end = now.endOf("day");
      }
      const filter = req.query.filter || "all";

      // Build a MongoDB query for search entries inside the selected day
      const queryObj = {
        childId,
        searchedAt: {
          $gte: start.toDate(),
          $lte: end.toDate(),
        },
      };

      // Filter safe/unsafe based on flag
      if (filter === "safe") {
        queryObj.isUnsafe = false;
      } else if (filter === "unsafe") {
        queryObj.isUnsafe = true;
      }

      // Fetch search entries from DB
      const docs = await SearchQueryEntry.find(queryObj)
        .sort({ searchedAt: -1 }) // newest first
        .lean();

      // Shape result for frontend
      const result = docs.map((d) => ({
        id: String(d._id),
        query: d.query || "",
        engine: d.engine || "",
        url: d.url || "",
        isUnsafe: !!d.isUnsafe,
        reason: d.reason || "",
        searchedAt: dayjs(d.searchedAt).tz("Asia/Kuala_Lumpur").format(),
      }));

      return res.json(result);
    } catch (err) {
      next(err);
    }
  }
);

// Export the router so it can be mounted in server.js as /activity
export default r;
