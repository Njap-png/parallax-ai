export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Use GET method' });
  }

  const GROQ_KEY = process.env.GROQ_API_KEY;
  const CODAPI_URL = process.env.CODAPI_URL || 'https://api.codapi.org/v1/';

  const health = {
    status: 'operational',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    api: {
      groq: { configured: !!GROQ_KEY, status: 'unknown' }
    },
    services: {
      cogi: 'operational',
      guardian: 'operational',
      docufy: 'operational',
      testpilot: 'operational',
      crawler: 'operational',
      agentswarm: 'operational',
      sandbox: 'operational',
      orchestrate: 'operational',
      chat: 'operational'
    }
  };

  if (GROQ_KEY) {
    try {
      const start = Date.now();
      const response = await fetch('https://api.groq.com/openai/v1/models', {
        headers: { 'Authorization': `Bearer ${GROQ_KEY}` }
      });
      const latency = Date.now() - start;

      if (response.ok) {
        health.api.groq = {
          configured: true,
          status: 'operational',
          latency: `${latency}ms`
        };
      } else {
        health.api.groq = {
          configured: true,
          status: 'degraded',
          error: `HTTP ${response.status}`
        };
        health.status = 'degraded';
      }
    } catch (err) {
      health.api.groq = {
        configured: true,
        status: 'error',
        error: err.message
      };
      health.status = 'degraded';
    }
  } else {
    health.api.groq = {
      configured: false,
      status: 'not_configured'
    };
  }

  res.json(health);
}
