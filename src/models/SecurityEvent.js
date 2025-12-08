// src/models/SecurityEvent.js
import mongoose from 'mongoose';

const SecurityEventSchema = new mongoose.Schema({
  familyId: { type: mongoose.Schema.Types.ObjectId, index: true, required: true },
  userId:   { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true, required: true },

  // e.g. "login_lock", "new_device", "late_login"
  type:     { type: String, required: true },

  // "low" | "medium" | "high"
  severity: { type: String, default: 'low' },

  message:  { type: String, required: true },

  details:  { type: mongoose.Schema.Types.Mixed, default: {} },

  createdAt: { type: Date, default: Date.now, index: { expires: '30d' }}
});

// helpful index to quickly get latest event of a type for a user
SecurityEventSchema.index({ userId: 1, type: 1, createdAt: -1 });

export default mongoose.model('SecurityEvent', SecurityEventSchema);
