export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();

  if (req.method !== 'GET' && req.method !== 'POST') {
    return res.status(405).json({ error: 'Use GET or POST' });
  }

  const GROQ_KEY = process.env.GROQ_API_KEY;
  const message = req.method === 'GET' 
    ? req.query.message || 'Say hello in a creative way'
    : (req.body?.message || 'Say hello in a creative way');

  if (!GROQ_KEY) {
    return res.status(500).json({
      success: false,
      error: 'GROQ_API_KEY not configured',
      message: 'Please configure GROQ_API_KEY in environment variables'
    });
  }

  try {
    const startTime = Date.now();
    
    const groqRes = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${GROQ_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: 'llama-3.3-70b-versatile',
        messages: [
          {
            role: 'system',
            content: 'You are a helpful AI assistant for Parallax Dominion. Be concise and helpful.'
          },
          { role: 'user', content: message }
        ],
        temperature: 0.7,
        max_tokens: 1024
      })
    });

    const latency = Date.now() - startTime;
    const data = await groqRes.json();

    if (!groqRes.ok) {
      return res.status(groqRes.status).json({
        success: false,
        error: data.error?.message || 'Groq API error',
        latency
      });
    }

    res.json({
      success: true,
      response: data.choices?.[0]?.message?.content || 'No response',
      model: 'llama-3.3-70b-versatile',
      usage: data.usage,
      latency: `${latency}ms`,
      api_status: 'operational'
    });
  } catch (err) {
    console.error('Groq API Error:', err);
    res.status(500).json({
      success: false,
      error: err.message || 'Failed to connect to Groq API',
      api_status: 'error'
    });
  }
}
