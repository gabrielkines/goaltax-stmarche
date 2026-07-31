const { verify } = require('./_auth');

module.exports = function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  if (req.method !== 'POST') return res.status(405).end();

  const { token } = req.body || {};
  const payload = verify(token);

  if (payload) {
    return res.status(200).json({ ok: true });
  } else {
    return res.status(401).json({ ok: false });
  }
};
