const CODAPI_URL = process.env.CODAPI_URL || 'https://api.codapi.org/v1/';
const CODAPI_KEY = process.env.CODAPI_KEY || '';

const PLAN_LIMITS = {
  free: 10,
  starter: 100,
  pro: 500,
  enterprise: Infinity
};

const languageMap = {
  javascript: 'javascript',
  python: 'python',
  typescript: 'typescript',
  java: 'java',
  cpp: 'cpp',
  c: 'c',
  go: 'go',
  rust: 'rust',
  ruby: 'ruby',
  php: 'php',
  bash: 'bash',
  sql: 'sqlite',
  sqlite: 'sqlite'
};

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') return res.status(200).end();

  if (req.method === 'GET') {
    return res.json({
      service: 'sandbox',
      status: 'operational',
      endpoint: '/api/sandbox',
      method: 'POST',
      supportedLanguages: Object.keys(languageMap),
      body: {
        language: 'python | javascript | ...',
        code: 'your code here',
        stdin: 'optional input'
      }
    });
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Use POST method' });
  }

  const { language, code, stdin = '' } = req.body || {};

  if (!code) {
    return res.status(400).json({ error: 'Code is required' });
  }

  const sandboxLang = languageMap[language?.toLowerCase()] || language?.toLowerCase();

  if (!sandboxLang) {
    return res.status(400).json({
      error: 'Unsupported language',
      supported: Object.keys(languageMap)
    });
  }

  const startTime = Date.now();

  try {
    const fetchOptions = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(CODAPI_KEY && { 'Authorization': `Bearer ${CODAPI_KEY}` })
      },
      body: JSON.stringify({
        sandbox: sandboxLang,
        command: 'run',
        files: { '': code },
        ...(stdin && { stdin })
      })
    };

    const response = await fetch(CODAPI_URL + 'exec', fetchOptions);

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      return res.status(response.status).json({
        error: errorData.error || 'Execution failed',
        code: response.status
      });
    }

    const data = await response.json();
    const executionTime = Date.now() - startTime;

    return res.json({
      success: data.status === 'ok',
      language: language?.toLowerCase(),
      sandbox: sandboxLang,
      status: data.status,
      stdout: data.stdout || '',
      stderr: data.stderr || '',
      exitCode: data.exit_code ?? (data.status === 'ok' ? 0 : 1),
      executionTime: `${executionTime}ms`,
      metadata: data.meta || null
    });

  } catch (err) {
    console.error('Codapi Error:', err);
    return res.status(500).json({
      error: 'Execution service unavailable',
      message: err.message
    });
  }
}
