// src/models/User.js
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';

const SessionSchema = new mongoose.Schema({
  deviceId: { type: String, required: true },
  deviceName: { type: String, default: null },
  platform:   { type: String, default: 'android' },
  firstSeenAt: { type: Date, default: Date.now },
  lastSeenAt:  { type: Date, default: Date.now },
  lastIp:      { type: String, default: null },
}, { _id: false });

const UserSchema = new mongoose.Schema({
  familyId: { type: mongoose.Schema.Types.ObjectId, index: true, required: true },

  email: { type: String, index: true, unique: true, required: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },

  role: { type: String, enum: ['Parent', 'Child'], default: 'Parent' },

  // Parent/Child relationships
  parentId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },

  // Privileges
  isSuperuser: { type: Boolean, default: false },

  // Client/session extras
  deviceIds: [{ type: String }],
  displayName: { type: String, trim: true, maxlength: 40 },

  twoFA: {
    enabled: { type: Boolean, default: false },
    secret: { type: String, default: null },
    pending: { type: Boolean, default: false }
  },

  reset: {
    code: { type: String },
    expires: { type: Date },
    attempts: { type: Number, default: 0 }
  },

  verify: {
    code: { type: String },
    expires: { type: Date , default: null},
    attempts: { type: Number, default: 0 }
  },

  tokenVersion: { type: Number, default: 0 },
  emailVerified: { type: Boolean, default: false },

  mfa: {
    enabled: { type: Boolean, default: false },
    secret: { type: String, default: null },
    recoveryCodes: { type: [String], default: [] }
  },

  // Session tracker
  sessions: [SessionSchema],

  // login security / intrusion tracking
  loginSecurity: {
    attempts:    { type: Number, default: 0 },   // wrong password attempts
    lockedUntil: { type: Date, default: null },  // if set & > now, login blocked
    lastLockAlertAt: { type: Date, default: null } // anti-spam for alerts
  },

  // per-user device limits (default set by role logic)
  deviceLimits: {
    maxDevices: { type: Number, default: 3 } // parents: 3, children: overridden to 2 on create
  },

  // sessions: [{
  //   deviceId: String,
  //   createdAt: { type: Date, default: Date.now },
  //   lastSeen: { type: Date, default: Date.now }
  // }],

  createdAt: { type: Date, default: Date.now }
});

// one superuser per family
UserSchema.index(
  { familyId: 1, isSuperuser: 1 },
  { unique: true, partialFilterExpression: { isSuperuser: true } }
);

UserSchema.index(
  { 'verify.expires': 1 },
  { expireAfterSeconds: 0, partialFilterExpression: { emailVerified: false } }
);

UserSchema.methods.comparePassword = function (plain) {
  return bcrypt.compare(plain, this.passwordHash);
};

UserSchema.statics.hashPassword = async function (plain) {
  return bcrypt.hash(plain, 12);
};

export default mongoose.model('User', UserSchema);