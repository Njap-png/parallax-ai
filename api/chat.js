export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  
  if (req.method === 'OPTIONS') return res.status(200).end();
  
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Use POST' });
  }
  
  const { messages } = req.body || {};
  
  if (!messages || !Array.isArray(messages)) {
    return res.status(400).json({ error: 'Messages array required' });
  }
  
  const GROQ_KEY = process.env.GROQ_KEY || 'gsk_DEMO';
  
  if (GROQ_KEY === 'gsk_DEMO') {
    const lastUserMsg = messages.filter(m => m.role === 'user').pop()?.content || '';
    const demoResponses = [
      "I understand you're asking about: " + lastUserMsg.substring(0, 50) + "...\n\nFor a complete answer, please configure your GROQ_KEY in Vercel environment variables.",
      "That's a great question! To get AI-powered responses, add your Groq API key as the GROQ_KEY environment variable in your Vercel project settings.",
      "```python\n# Example response\ndef solution():\n    return 'Configure GROQ_KEY for AI responses'\n\nprint(solution())\n```"
    ];
    const response = demoResponses[Math.floor(Math.random() * demoResponses.length)];
    return res.json({ response, usage: { total_tokens: 50 } });
  }
  
  try {
    const groqMessages = messages.map(m => ({
      role: m.role === 'system' ? 'system' : (m.role === 'assistant' ? 'assistant' : 'user'),
      content: m.content
    }));
    
    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${GROQ_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: 'llama-3.3-70b-versatile',
        messages: groqMessages,
        max_tokens: 4096,
        temperature: 0.7
      })
    });
    
    if (!response.ok) {
      const err = await response.json();
      return res.status(500).json({ error: err.error?.message || 'Groq API error' });
    }
    
    const data = await response.json();
    res.json({
      response: data.choices[0].message.content,
      usage: data.usage,
      model: data.model
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to generate response' });
  }
}
