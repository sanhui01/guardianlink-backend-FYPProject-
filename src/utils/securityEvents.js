// src/utils/securityEvents.js
import User from '../models/User.js';
import PushToken from '../models/PushToken.js';
import SecurityEvent from '../models/SecurityEvent.js';
import { sendPushToTokens } from './push.js';
import { sendSecurityAlertEmail } from './mailer.js';

/**
 * Create a SecurityEvent and send notifications.
 * @param {Object} opts
 * @param {import('../models/User.js').default} opts.user - user document triggering event
 * @param {string} opts.type - "login_lock" | "new_device" | "late_login" | ...
 * @param {string} opts.severity - "low" | "medium" | "high"
 * @param {string} opts.message - human-friendly message
 * @param {Object} [opts.details] - any extra structured fields
 */
export async function recordSecurityEventAndNotify({ user, type, severity = 'low', message, details = {} }) {
  if (!user?.familyId) return;

  const familyId = user.familyId;
  const userId   = user._id;

  const event = await SecurityEvent.create({
    familyId,
    userId,
    type,
    severity,
    message,
    details
  });

  // Who to notify?
  // If child account -> notify all parents in family
  // If parent account -> notify that parent (and optionally other parents)
  let targets;
  if (user.role === 'Child') {
    targets = await User.find({ familyId, role: 'Parent' }).select('_id email');
  } else {
    targets = [user];
  }

  const targetIds   = targets.map(t => t._id);
  const targetEmails = targets.map(t => t.email).filter(Boolean);

  // Fetch push tokens for all these users
  const tokenDocs = await PushToken.find({ userId: { $in: targetIds } }).lean();
  const tokens = tokenDocs.map(t => t.fcmToken);

  const notifTitle = 'GuardianLink Security Alert';
  const notifBody  = message;

  // FCM push
  if (tokens.length) {
    await sendPushToTokens(tokens, {
      title: notifTitle,
      body: notifBody
    }, {
      type: `security_${type}`,
      userId: userId.toString(),
      severity,
      message,
    });
  }

  // Email (only for medium/high severity)
  if (severity === 'high' || severity === 'medium') {
    for (const email of targetEmails) {
      await sendSecurityAlertEmail(email, notifTitle, message);
    }
  }

  return event;
}
