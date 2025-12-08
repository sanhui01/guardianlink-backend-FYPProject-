// src/utils/push.js
import fs from "fs";
import { GoogleAuth } from "google-auth-library";

const saPath =
  process.env.FCM_SERVICE_ACCOUNT_PATH ||
  process.env.GOOGLE_APPLICATION_CREDENTIALS;

if (!saPath) {
  console.warn(
    "⚠ FCM: no FCM_SERVICE_ACCOUNT_PATH/GOOGLE_APPLICATION_CREDENTIALS set; pushes will be skipped"
  );
}

let cachedProjectId = null;

function getProjectId() {
  if (!saPath) return null;
  if (cachedProjectId) return cachedProjectId;

  try {
    const raw = fs.readFileSync(saPath, "utf8");
    const json = JSON.parse(raw);
    cachedProjectId = json.project_id;
    if (!cachedProjectId) {
      console.warn("⚠ FCM: project_id missing from service account JSON");
    }
    return cachedProjectId;
  } catch (e) {
    console.error("❌ FCM: failed to read service account file:", e.message);
    return null;
  }
}

const auth = saPath
  ? new GoogleAuth({
      keyFile: saPath,
      scopes: ["https://www.googleapis.com/auth/firebase.messaging"],
    })
  : null;

export async function sendPushToTokens(tokens, notification = {}, data = {}) {
  if (!tokens?.length) return;
  if (!auth || !saPath) {
    console.warn("⚠ FCM: auth not configured; skipping push");
    return;
  }

  const projectId = getProjectId();
  if (!projectId) return;

  const client = await auth.getClient();
  const url = `https://fcm.googleapis.com/v1/projects/${projectId}/messages:send`;

  for (const token of tokens) {
    try {
      const msg = {
        message: {
          token,
          notification: {
            title: notification.title || "",
            body: notification.body || "",
          },
          data: Object.fromEntries(
            Object.entries(data).map(([k, v]) => [String(k), String(v)])
          ),
        },
      };

      const res = await client.request({
        url,
        method: "POST",
        data: msg,
      });

      console.log("✅ FCM v1 push ok:", res.data?.name || "(no name)");
    } catch (e) {
      const errData = e.response?.data;
      console.error("❌ FCM v1 push error:", errData || e.message);

      // If token is invalid, keep going (don't break the loop)
      // Optional: you can delete invalid tokens here if you want.
    }
  }
}
