// src/middleware/validators.js
export const schemas = {
  register: (body) => {
    if (!body?.email || !body?.password) throw new Error('email and password required');
  },
  login: (body) => {
    if (!body?.email || !body?.password) throw new Error('email and password required');
  },
  reset: (body) => {
    if (!body?.email || !body?.code || !body?.newPassword) throw new Error('missing fields');
  }
};

export function validate(schema) {
  return (req, res, next) => {
    try { schema(req.body); next(); }
    catch (e) { res.status(400).json({ message: e.message || 'Invalid payload' }); }
  };
}