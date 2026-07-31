const crypto = require('crypto');
const SECRET = process.env.JWT_SECRET;
const EXPIRES_MS = 2 * 60 * 60 * 1000; // 2 horas

if (!SECRET) {
  throw new Error('JWT_SECRET não definido. Configure a variável de ambiente no Vercel antes de fazer deploy.');
}

function sign(payload) {
  const fullPayload = { ...payload, exp: Date.now() + EXPIRES_MS };
  const data = Buffer.from(JSON.stringify(fullPayload)).toString('base64');
  const sig  = crypto.createHmac('sha256', SECRET).update(data).digest('hex');
  return `${data}.${sig}`;
}

function verify(token) {
  if (!token) return null;
  try {
    const dot  = token.lastIndexOf('.');
    const data = token.slice(0, dot);
    const sig  = token.slice(dot + 1);
    const expected = crypto.createHmac('sha256', SECRET).update(data).digest('hex');
    if (sig !== expected) return null;
    const payload = JSON.parse(Buffer.from(data, 'base64').toString());
    if (Date.now() > payload.exp) return null;
    return payload;
  } catch { return null; }
}

function fromRequest(req) {
  const auth = req.headers.authorization || '';
  if (auth.startsWith('Bearer ')) return verify(auth.slice(7));
  return null;
}

module.exports = { sign, verify, fromRequest };
