export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Use POST' });
  }

  const { name, email, message, type = 'contact' } = req.body || {};

  if (!name || !email || !message) {
    return res.status(400).json({ error: 'All fields required' });
  }

  console.log(`[${type.toUpperCase()}] ${name} <${email}>: ${message}`);

  if (type === 'payment' || type === 'subscription') {
    console.log(`Subscription event logged for ${email}`);
  }

  res.json({ 
    success: true, 
    message: type === 'payment' 
      ? 'Payment notification received' 
      : 'Message received. We will respond within 24 hours.' 
  });
}
