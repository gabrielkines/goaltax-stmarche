const { sign } = require('./_auth');

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  if (req.method !== 'POST') return res.status(405).json({ erro: 'Method not allowed' });

  const { password, email } = req.body || {};
  const APP_PASSWORD = process.env.APP_PASSWORD;

  if (!APP_PASSWORD || password !== APP_PASSWORD) {
    return res.status(401).json({ erro: 'Senha incorreta. Verifique com a GoalTax.' });
  }

  if (!email || !email.trim() || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
    return res.status(400).json({ erro: 'Informe um e-mail válido para continuar.' });
  }

  const emailClean = email.trim().toLowerCase();
  const token = sign({ email: emailClean, role: 'user', iat: Date.now() });

  return res.status(200).json({ token, email: emailClean });
};
