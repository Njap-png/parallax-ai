const ADMIN_EMAIL = 'parallaxstudio.ai@gmail.com';
const ADMIN_PASS = 'Parallax2026!';

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  
  if (req.method === 'OPTIONS') return res.status(200).end();
  
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Use POST' });
  }
  
  const { email, password } = req.body || {};
  
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }
  
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }
  
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }
  
  if (email === ADMIN_EMAIL && password === ADMIN_PASS) {
    res.json({ 
      success: true, 
      token: 'admin_token_' + Date.now(),
      user: { id: 'admin_001', email: ADMIN_EMAIL, name: 'Admin' }
    });
    return;
  }
  
  res.json({ 
    success: true, 
    token: 'user_token_' + Date.now(),
    user: { id: 'user_' + Date.now(), email: email, name: email.split('@')[0] }
  });
}
