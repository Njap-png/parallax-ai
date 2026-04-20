const GROQ_KEY = process.env.GROQ_API_KEY;

if (!GROQ_KEY) {
  console.warn('[WARN] GROQ_API_KEY not configured. AI services will fail.');
}

const MODELS = {
  fast: 'llama-3.1-8b-instant',
  balanced: 'llama-3.3-70b-versatile',
  power: 'mixtral-8x7b-32768'
};

const SYSTEM_PROMPTS = {
  cogi: `You are COGI, the most advanced AI code generation engine. You produce production-ready, elegant, and efficient code.

Your capabilities:
• Write complete applications from scratch
• Implement algorithms and data structures
• Create REST APIs and microservices
• Build frontend components and UIs
• Write backend services and databases
• Implement authentication and security
• Create tests and documentation

Guidelines:
- Output ONLY the code (no explanations unless requested)
- Use modern syntax and best practices
- Include error handling
- Write clean, readable, maintainable code
- Follow language conventions
- Add type hints for type safety
- Use async/await appropriately
- Handle edge cases

Languages: JavaScript, TypeScript, Python, Go, Rust, Java, C++, C#, PHP, Ruby, Swift, Kotlin, SQL`,

  guardian: `You are GUARDIAN, a world-class security expert. You find vulnerabilities and provide actionable fixes.

Security expertise:
• SQL Injection, XSS, CSRF attacks
• Authentication bypass, session hijacking
• Rate limiting, DoS prevention
• Input validation, sanitization
• Encryption, secure storage
• API security, CORS policies
• Dependency vulnerabilities
• Secure coding practices

For each vulnerability provide:
1. Severity (CRITICAL/HIGH/MEDIUM/LOW)
2. Description of the risk
3. Exact location in code
4. Proof of concept
5. Step-by-step fix
6. Prevention measures`,

  docufy: `You are DOCUFY, a professional technical writer. You create comprehensive, beautiful documentation.

Documentation types:
• API Documentation (OpenAPI/Swagger style)
• README files with setup guides
• Function/class documentation
• Architecture diagrams (ASCII)
• User guides and tutorials
• Changelogs and release notes
• Code comments and inline docs
• System design documents

Format: Clean Markdown with:
• Proper headings hierarchy
• Code blocks with syntax highlighting
• Tables for parameters
• Examples for every feature
• Badges and badges`,

  testpilot: `You are TEST PILOT, a senior QA engineer with 15+ years experience. You write bulletproof tests.

Testing expertise:
• Unit testing, integration testing
• End-to-end testing
• Test-driven development
• Mocking and stubbing
• Property-based testing
• Performance testing
• Security testing
• Edge case coverage

Test quality:
- 100% code coverage targets
- Descriptive test names
- Arrange-Act-Assert pattern
- Independent, isolated tests
- Proper setup/teardown
- Meaningful assertions
- Performance benchmarks`,

  crawler: `You are CRAWLER, an expert web scraper and data extractor. You find and extract structured data from any webpage.

Capabilities:
• Extract titles, metadata, content
• Find all links and resources
• Identify forms and inputs
• Detect JavaScript dependencies
• Map page structure
• Find API endpoints
• Extract structured data (JSON-LD, schema.org)
• Monitor for changes`,

  agentswarm: `You are the SWARM COORDINATOR, orchestrating multiple AI agents to solve complex problems.

Agent types:
• ARCHITECT - Designs scalable systems
• CODER - Implements features
• REVIEWER - Quality assurance
• TESTER - Test coverage
• DOCS - Documentation
• OPTIMIZER - Performance
• SECURITY - Vulnerability hunting
• ANALYST - Data insights

Each agent is an expert in their domain, working together to deliver complete solutions.`
};

const AGENTS = {
  architect: {
    name: 'Architect',
    icon: '🏗️',
    color: '#a855f7',
    role: 'System Designer',
    prompt: `You are an expert software architect with deep knowledge of:
• Microservices and distributed systems
• Event-driven architecture
• Domain-driven design
• Clean architecture patterns
• Scalability principles
• Cloud-native design
• Database design (SQL/NoSQL)
• API design (REST, GraphQL, gRPC)

Create comprehensive architecture plans with:
- Component diagrams (ASCII art)
- Data flow diagrams
- Technology recommendations
- Scalability considerations
- Security architecture
- Deployment strategy`
  },
  coder: {
    name: 'Coder',
    icon: '⚡',
    color: '#00ff88',
    role: 'Implementation Expert',
    prompt: `You are a senior software engineer expert in:
• Multiple programming languages
• Design patterns (GoF, enterprise)
• Clean code principles
• Refactoring techniques
• Code smells and fixes
• Performance optimization
• Modern frameworks
• Best practices

Write production-ready code that is:
- Clean and readable
- Well-structured
- Properly typed
- Error handled
- Tested
- Documented`
  },
  reviewer: {
    name: 'Reviewer',
    icon: '🔍',
    color: '#00ffff',
    role: 'Code Quality Expert',
    prompt: `You are a code reviewer with eagle eyes for:
• Bug detection
• Code smells
• Anti-patterns
• Performance issues
• Security vulnerabilities
• Maintainability concerns
• Best practice violations
• Logic errors

Provide detailed, constructive feedback with:
- Specific line references
- Severity levels
- Code examples
- Corrected versions
- Learning resources`
  },
  tester: {
    name: 'Tester',
    icon: '🧪',
    color: '#28c840',
    role: 'QA Engineer',
    prompt: `You are a testing expert specializing in:
• Unit testing (Jest, pytest, JUnit)
• Integration testing
• E2E testing (Playwright, Cypress)
• Test coverage analysis
• Property-based testing
• Performance testing
• Security testing
• Mutation testing

Create comprehensive test suites with:
- High coverage
- Edge cases
- Happy paths
- Error scenarios
- Performance benchmarks`
  },
  docs: {
    name: 'Documenter',
    icon: '📝',
    color: '#febc2e',
    role: 'Technical Writer',
    prompt: `You are a technical documentation expert creating:
• API documentation
• README files
• Architecture docs
• User guides
• Tutorial articles
• Changelogs
• Code comments
• Inline documentation

Write clear, concise, complete documentation with:
- Proper Markdown formatting
- Code examples
- Visual diagrams
- Tables and lists
- Search optimization`
  },
  optimizer: {
    name: 'Optimizer',
    icon: '🚀',
    color: '#ff9500',
    role: 'Performance Engineer',
    prompt: `You are a performance optimization expert skilled in:
• Algorithm optimization
• Memory management
• Database query optimization
• Caching strategies
• CDN integration
• Lazy loading
• Code splitting
• Bundle optimization

Identify bottlenecks and provide:
- Profiling insights
- Specific optimizations
- Before/after comparisons
- Performance metrics
- Implementation guides`
  },
  security: {
    name: 'Security',
    icon: '🛡️',
    color: '#ff5f57',
    role: 'Security Expert',
    prompt: `You are a security specialist expert in:
• Penetration testing
• Vulnerability assessment
• Secure coding
• OWASP Top 10
• Cryptography
• Authentication systems
• Authorization patterns
• API security

Find vulnerabilities and provide:
- Risk assessment
- Attack scenarios
• Proof of concepts
- Mitigation strategies
- Security checklists
- Compliance guidance`
  },
  analyst: {
    name: 'Analyst',
    icon: '📊',
    color: '#a855f7',
    role: 'Data Analyst',
    prompt: `You are a data analyst expert in:
• Statistical analysis
• Data visualization
• Trend identification
• Pattern recognition
• Report generation
• KPI tracking
• A/B testing analysis
• Business intelligence

Create insights through:
- Data summaries
- Trend analysis
- Visualizations (ASCII)
- Recommendations
- Action items
- Risk assessments`
  }
};

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();

  const { service, message, language, mode, code, url, task, agents: requestedAgents, framework, model: requestedModel, stream, context } = req.body || {};

  const model = MODELS[requestedModel] || MODELS.balanced;

  try {
    switch (service) {
      case 'cogi':
        return await handleCogi(res, { message, language, mode, model });
      case 'guardian':
        return await handleGuardian(res, { code, model });
      case 'docufy':
        return await handleDocufy(res, { code, language, mode, model });
      case 'testpilot':
        return await handleTestpilot(res, { code, framework, mode, model });
      case 'crawler':
        return await handleCrawler(res, { url });
      case 'agentswarm':
        return await handleAgentSwarm(res, { task, agents: requestedAgents, model });
      case 'orchestrate':
        return await handleOrchestrate(res, { task, services: requestedAgents, model });
      case 'chat':
        return await handleChat(res, { message, context });
      default:
        return res.status(400).json({ 
          error: 'Invalid service',
          available: ['cogi', 'guardian', 'docufy', 'testpilot', 'crawler', 'agentswarm', 'orchestrate', 'chat']
        });
    }
  } catch (err) {
    console.error(`[${service}] Error:`, err);
    res.status(500).json({ error: 'Service error', message: err.message });
  }
}

async function callGroq(messages, model = 'llama-3.3-70b-versatile', maxTokens = 4096) {
  if (!GROQ_KEY) throw new Error('GROQ_API_KEY not configured');

  const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${GROQ_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ model, messages, max_tokens: maxTokens, temperature: 0.7 })
  });

  if (!response.ok) {
    const err = await response.json();
    throw new Error(err.error?.message || 'Groq API error');
  }

  return response.json();
}

async function handleCogi(res, { message, language, mode, model }) {
  if (!message) return res.status(400).json({ error: 'Message required' });

  const modeInstructions = {
    code: 'Generate complete, working code. No explanations unless asked.',
    explain: 'Explain how the code works, what it does, and why it was designed that way.',
    debug: 'Analyze the code, identify bugs, explain what went wrong, and provide corrected code.',
    optimize: 'Improve the code for performance, readability, and maintainability. Show before/after.',
    review: 'Critically review the code and provide detailed feedback with specific improvement suggestions.',
    refactor: 'Completely refactor the code to follow best practices and clean architecture.',
    test: 'Generate comprehensive tests for the provided code.',
    document: 'Add thorough documentation, comments, and type hints to the code.'
  };

  const langContext = language ? `Target language: ${language.toUpperCase()}` : 'Use the most appropriate language';

  const data = await callGroq([
    { role: 'system', content: SYSTEM_PROMPTS.cogi },
    { role: 'user', content: `${langContext}\nMode: ${mode || 'code'}\n\n${modeInstructions[mode] || modeInstructions.code}\n\nRequest:\n${message}` }
  ], model, 4096);

  res.json({
    success: true,
    service: 'cogi',
    mode: mode || 'code',
    response: data.choices[0].message.content,
    model,
    language: language || 'auto',
    tokens: data.usage?.total_tokens || 0,
    timestamp: new Date().toISOString()
  });
}

async function handleGuardian(res, { code, model }) {
  if (!code) return res.status(400).json({ error: 'Code required' });

  const analysis = await callGroq([
    { role: 'system', content: SYSTEM_PROMPTS.guardian },
    { role: 'user', content: `Analyze this code for security vulnerabilities:\n\n${code.slice(0, 4000)}\n\nProvide a structured security report with severity levels, descriptions, and fixes.` }
  ], model, 2048);

  const quickScan = await scanPatterns(code);

  res.json({
    success: true,
    service: 'guardian',
    aiAnalysis: analysis.choices[0].message.content,
    patternScan: quickScan,
    score: calculateSecurityScore(quickScan),
    recommendations: generateRecommendations(quickScan),
    timestamp: new Date().toISOString()
  });
}

function scanPatterns(code) {
  const patterns = [
    { name: 'SQL Injection', severity: 'CRITICAL', regex: /(?:\b(?:select|insert|update|delete|drop)\b.*(?:\$\{|'|\"|\+).*(?:\bfrom|where)\b)|(?:query|execute|exec)\s*\(\s*['"]?\s*(?:select|insert|update|delete|drop)/gi },
    { name: 'Command Injection', severity: 'CRITICAL', regex: /(?:exec|eval|system|passthru|shell_exec|popen)\s*\(\s*(?:\$\{|`|\$)/gi },
    { name: 'XSS - innerHTML', severity: 'HIGH', regex: /\.innerHTML\s*=/gi },
    { name: 'XSS - eval with user input', severity: 'HIGH', regex: /eval\s*\(\s*(?:document\.|window\.|location\.)/gi },
    { name: 'Hardcoded Secrets', severity: 'CRITICAL', regex: /(?:password|secret|api[_-]?key|token|auth)\s*[=:]\s*['"][a-zA-Z0-9_\-]{8,}['"]/gi },
    { name: 'Insecure Random', severity: 'MEDIUM', regex: /Math\.random\s*\(\s*\)/gi },
    { name: 'Weak Cryptography', severity: 'HIGH', regex: /(?:md5|sha1|des|rc4)\s*\(/gi },
    { name: 'Path Traversal', severity: 'HIGH', regex: /(?:readFile|readFileSync|open|include|require)\s*\(\s*(?:req\.|params\.|query\.)/gi },
    { name: 'Regex DoS', severity: 'MEDIUM', regex: /(?:\.\*|\.\+)(?:\{[0-9]+,\}|\?)+\s*(?:\||\(|\[)/gi },
    { name: 'Prototype Pollution', severity: 'HIGH', regex: /Object\.assign\s*\(\s*(?:req|body|params)/gi },
    { name: 'Race Condition', severity: 'MEDIUM', regex: /(?:read|write|check)\s*.*\n\s*(?:write|read|delete)\s*\(\s*same/gi },
    { name: 'Missing Rate Limiting', severity: 'LOW', regex: /router\.(post|put|delete|patch)/gi },
    { name: 'No CSRF Protection', severity: 'MEDIUM', regex: /(?:app|express|koa)\.(use|post|put|delete)\s*\([^,)]+\)\s*(?!.*csrf|csrfToken|xsrf)/gi },
    { name: 'Insecure Cookie', severity: 'MEDIUM', regex: /cookie\s*\(\s*\{[^}]*(?!httponly|secure)/gi },
    { name: 'Verbose Errors', severity: 'LOW', regex: /(?:console\.(?:log|debug)|logger\.(?:log|debug))\s*\(\s*(?:err|error|exception)/gi }
  ];

  const findings = [];

  for (const pattern of patterns) {
    const matches = code.match(pattern.regex);
    if (matches) {
      findings.push({
        type: pattern.name,
        severity: pattern.severity,
        count: matches.length,
        matches: matches.slice(0, 3),
        remediation: getRemediation(pattern.name)
      });
    }
  }

  return findings;
}

function getRemediation(type) {
  const remediations = {
    'SQL Injection': 'Use parameterized queries or prepared statements. Never concatenate user input into SQL.',
    'Command Injection': 'Avoid eval() and shell execution. Use safe APIs or sanitization libraries.',
    'XSS - innerHTML': 'Use textContent instead of innerHTML, or sanitize HTML with DOMPurify.',
    'XSS - eval with user input': 'Never pass user input to eval(). Use JSON.parse() for objects.',
    'Hardcoded Secrets': 'Use environment variables or secret management services (AWS Secrets, Vault).',
    'Insecure Random': 'Use crypto.randomBytes() or crypto.randomUUID() for security-sensitive random values.',
    'Weak Cryptography': 'Use AES-256-GCM or ChaCha20-Poly1305. Never use MD5 or SHA1 for security.',
    'Path Traversal': 'Validate and sanitize file paths. Use path.resolve() and whitelist allowed directories.',
    'Prototype Pollution': 'Deep clone user input with JSON.parse(JSON.stringify()) or use safe clone libraries.',
    'Race Condition': 'Use database transactions or locking mechanisms for concurrent operations.',
    'Missing Rate Limiting': 'Implement rate limiting with express-rate-limit or similar.',
    'No CSRF Protection': 'Add CSRF tokens or use SameSite cookies.',
    'Insecure Cookie': 'Set HttpOnly, Secure, and SameSite flags on cookies.',
    'Verbose Errors': 'Remove debug logging in production. Use structured logging libraries.'
  };
  return remediations[type] || 'Review and fix this security issue.';
}

function calculateSecurityScore(scan) {
  const weights = { CRITICAL: 30, HIGH: 20, MEDIUM: 10, LOW: 5 };
  let score = 100;
  for (const finding of scan) {
    score -= weights[finding.severity] * Math.min(finding.count, 3);
  }
  return Math.max(0, score);
}

function generateRecommendations(scan) {
  const recs = [];
  const severities = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };

  for (const finding of scan) {
    severities[finding.severity]++;
    recs.push({
      priority: finding.severity,
      issue: finding.type,
      fix: finding.remediation,
      occurrences: finding.count
    });
  }

  if (severities.CRITICAL > 0) {
    recs.unshift({ priority: 'CRITICAL', issue: 'Address all CRITICAL vulnerabilities immediately', fix: 'Do not deploy until critical issues are resolved.', occurrences: severities.CRITICAL });
  }

  return recs.sort((a, b) => {
    const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    return order[a.priority] - order[b.priority];
  });
}

async function handleDocufy(res, { code, language, mode, model }) {
  if (!code) return res.status(400).json({ error: 'Code required' });

  const docType = mode || 'full';

  const data = await callGroq([
    { role: 'system', content: SYSTEM_PROMPTS.docufy },
    { role: 'user', content: `Generate comprehensive ${docType} documentation for this code:\n\nLanguage: ${language || 'auto-detect'}\n\n\`\`\`\n${code.slice(0, 4000)}\n\`\`\`\n\nInclude: overview, installation, usage examples, API reference, and diagrams where helpful.` }
  ], model, 4096);

  res.json({
    success: true,
    service: 'docufy',
    documentation: data.choices[0].message.content,
    type: docType,
    language: language || 'auto-detected',
    tokens: data.usage?.total_tokens || 0,
    timestamp: new Date().toISOString()
  });
}

async function handleTestpilot(res, { code, framework, mode, model }) {
  if (!code) return res.status(400).json({ error: 'Code required' });

  const testType = mode || 'comprehensive';
  const fw = framework || 'jest';

  const data = await callGroq([
    { role: 'system', content: SYSTEM_PROMPTS.testpilot },
    { role: 'user', content: `Generate ${testType} tests in ${fw} for this code:\n\n\`\`\`\n${code.slice(0, 3000)}\n\`\`\`\n\nRequirements:
- Use ${fw} testing framework
- Include edge cases and error scenarios
- Add setup/teardown where needed
- Include performance benchmarks if applicable
- Achieve maximum coverage` }
  ], model, 4096);

  res.json({
    success: true,
    service: 'testpilot',
    tests: data.choices[0].message.content,
    framework: fw,
    type: testType,
    tokens: data.usage?.total_tokens || 0,
    timestamp: new Date().toISOString()
  });
}

async function handleCrawler(res, { url }) {
  if (!url) return res.status(400).json({ error: 'URL required' });

  try {
    const response = await fetch(url, {
      headers: { 'User-Agent': 'Parallax-CRAWLER/2.0 (AI-Powered)' },
      timeout: 10000
    });

    const html = await response.text();

    const structured = extractStructuredData(html);
    const aiInsights = await analyzeWithAI(html.slice(0, 3000), url);

    res.json({
      success: true,
      service: 'crawler',
      url,
      status: response.status,
      title: extractTitle(html),
      description: extractMeta(html, 'description'),
      keywords: extractMeta(html, 'keywords'),
      structured,
      links: {
        internal: extractLinks(html, url, 'internal').slice(0, 20),
        external: extractLinks(html, url, 'external').slice(0, 10),
        total: extractLinks(html, url, 'all').length
      },
      resources: {
        images: extractImages(html).slice(0, 10),
        scripts: extractScripts(html),
        styles: extractStyles(html),
        fonts: extractFonts(html)
      },
      forms: extractForms(html),
      social: extractSocial(html),
      aiAnalysis: aiInsights,
      techStack: detectTechStack(html),
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({ error: `Crawl failed: ${err.message}` });
  }
}

function extractTitle(html) {
  const match = html.match(/<title[^>]*>([^<]+)<\/title>/i);
  return match ? match[1].trim() : null;
}

function extractMeta(html, name) {
  const patterns = [
    new RegExp(`<meta[^>]+name=["']${name}["'][^>]+content=["']([^"']+)["']`, 'i'),
    new RegExp(`<meta[^>]+content=["']([^"']+)["'][^>]+name=["']${name}["']`, 'i')
  ];
  for (const p of patterns) {
    const match = html.match(p);
    if (match) return match[1].trim();
  }
  return null;
}

function extractStructuredData(html) {
  const data = {};

  const jsonLd = html.match(/<script[^>]+type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi);
  if (jsonLd) {
    data.jsonLd = jsonLd.map(s => {
      try { return JSON.parse(s.replace(/<[^>]+>/g, '')); } catch { return null; }
    }).filter(Boolean);
  }

  const microdata = html.match(/itemscope[^>]*>([\s\S]*?)<\/div>/gi);
  if (microdata) data.microdata = `${microdata.length} items found`;

  return data;
}

function extractLinks(html, baseUrl, type) {
  const base = new URL(baseUrl);
  const links = [];
  const regex = /<a[^>]+href=["']([^"']+)["'][^>]*>/gi;
  let match;

  while ((match = regex.exec(html)) !== null) {
    try {
      const href = match[1];
      if (href.startsWith('#') || href.startsWith('mailto:') || href.startsWith('tel:')) continue;

      const fullUrl = new URL(href, baseUrl);
      const isInternal = fullUrl.hostname === base.hostname;

      if (type === 'internal' && isInternal) links.push(fullUrl.href);
      else if (type === 'external' && !isInternal) links.push(fullUrl.href);
      else if (type === 'all') links.push(fullUrl.href);
    } catch {}
  }

  return [...new Set(links)];
}

function extractImages(html) {
  return html.match(/<img[^>]+src=["']([^"']+)["']/gi)?.slice(0, 20).map(s => {
    const match = s.match(/src=["']([^"']+)["']/);
    return match ? match[1] : null;
  }).filter(Boolean) || [];
}

function extractScripts(html) {
  return html.match(/<script[^>]+src=["']([^"']+)["']/gi)?.map(s => {
    const match = s.match(/src=["']([^"']+)["']/);
    return match ? match[1] : null;
  }).filter(Boolean) || [];
}

function extractStyles(html) {
  return html.match(/<link[^>]+href=["'][^"']*\.css[^"']*["'][^>]*>/gi)?.map(s => {
    const match = s.match(/href=["']([^"']+)["']/);
    return match ? match[1] : null;
  }).filter(Boolean) || [];
}

function extractFonts(html) {
  const fontLinks = html.match(/fonts\.(?:googleapis|gstatic)\.com[^\s"']+/gi) || [];
  return [...new Set(fontLinks)];
}

function extractForms(html) {
  const forms = [];
  const formRegex = /<form[^>]*>([\s\S]*?)<\/form>/gi;
  let match;

  while ((match = formRegex.exec(html)) !== null) {
    const inputs = match[1].match(/<input[^>]+>/gi) || [];
    forms.push({
      action: match[0].match(/action=["']([^"']+)["']/)?.[1],
      method: match[0].match(/method=["']([^"']+)["']/)?.[1] || 'GET',
      inputs: inputs.map(inp => ({
        name: inp.match(/name=["']([^"']+)["']/)?.[1],
        type: inp.match(/type=["']([^"']+)["']/)?.[1] || 'text',
        required: inp.includes('required')
      })).filter(i => i.name)
    });
  }

  return forms;
}

function extractSocial(html) {
  const social = {};
  const patterns = [
    ['twitter', /twitter\.com\/[^\/]+\/status/],
    ['facebook', /facebook\.com\/[^\/]+\/posts/],
    ['linkedin', /linkedin\.com\/[^\/]+\/[^\/]+/],
    ['instagram', /instagram\.com\/[^\/]+/]
  ];

  for (const [name, regex] of patterns) {
    if (regex.test(html)) social[name] = true;
  }

  const ogImage = html.match(/<meta[^>]+property=["']og:image["'][^>]+content=["']([^"']+)["']/i)?.[1];
  if (ogImage) social.ogImage = ogImage;

  return social;
}

function detectTechStack(html) {
  const stack = [];

  if (html.includes('react') || html.includes('React')) stack.push('React');
  if (html.includes('vue') || html.includes('Vue')) stack.push('Vue.js');
  if (html.includes('angular')) stack.push('Angular');
  if (html.includes('nextjs') || html.includes('__NEXT_DATA__')) stack.push('Next.js');
  if (html.includes('gatsby')) stack.push('Gatsby');
  if (html.includes('wp-content') || html.includes('wordpress')) stack.push('WordPress');
  if (html.includes('shopify')) stack.push('Shopify');
  if (html.includes('_nuxt') || html.includes('__NUXT__')) stack.push('Nuxt.js');
  if (html.includes('gatsby') || html.includes('___gatsby')) stack.push('Gatsby');
  if (html.includes('cloudflare')) stack.push('Cloudflare');
  if (html.includes('google-tag-manager')) stack.push('Google Tag Manager');
  if (html.includes('analytics')) stack.push('Analytics');

  return stack;
}

async function analyzeWithAI(htmlSnippet, url) {
  if (!GROQ_KEY) return null;

  try {
    const analysis = await callGroq([
      { role: 'system', content: 'You are a web analyst. Analyze this HTML and provide insights about the website\'s purpose, quality, and notable features.' },
      { role: 'user', content: `Analyze this website: ${url}\n\n${htmlSnippet.slice(0, 2000)}` }
    ], 'llama-3.1-8b-instant', 500);

    return analysis.choices[0].message.content;
  } catch {
    return null;
  }
}

const LANGUAGE_CONTEXT = {
  javascript: 'Write all code in JavaScript (ES6+). Use modern JS patterns, async/await, and Node.js compatible syntax.',
  typescript: 'Write all code in TypeScript with strict typing. Include interfaces, types, and comprehensive type annotations.',
  python: 'Write all code in Python. Use modern Python 3.10+ features, type hints, and follow PEP 8 conventions.',
  rust: 'Write all code in Rust. Use idiomatic Rust patterns, proper ownership, and include Cargo.toml where needed.',
  go: 'Write all code in Go. Use idiomatic Go patterns, goroutines where appropriate, and follow Go conventions.',
  java: 'Write all code in Java. Use modern Java 17+ features, proper OOP patterns, and Maven/Gradle config.',
  cpp: 'Write all code in C++. Use modern C++20 features, proper memory management, and include build instructions.',
  csharp: 'Write all code in C#. Use .NET 6+/8 patterns, LINQ, and async/await properly.',
  php: 'Write all code in PHP 8+. Use modern PHP patterns, PSR standards, and Laravel-compatible syntax.',
  ruby: 'Write all code in Ruby. Use Ruby 3.x patterns, blocks, and follow Ruby conventions.',
  swift: 'Write all code in Swift. Use modern Swift 5.9+ patterns, optionals, and SwiftUI-compatible code.',
  kotlin: 'Write all code in Kotlin. Use Kotlin 1.9+ features, coroutines, and Android-compatible code.',
  sql: 'Write SQL queries and database scripts. Include CREATE TABLE, SELECT, JOIN, and optimization notes.',
  html: 'Write HTML5 and CSS3 code. Use semantic HTML, modern CSS (flexbox/grid), and responsive design.',
  bash: 'Write Bash shell scripts. Use modern Bash 5+ features, proper error handling, and shebang.'
};

async function handleAgentSwarm(res, { task, agents, model, language }) {
  if (!task) return res.status(400).json({ error: 'Task required' });

  const selectedAgents = (agents || ['coder', 'reviewer', 'tester']).slice(0, 6);
  const startTime = Date.now();
  const langContext = language && LANGUAGE_CONTEXT[language] ? `\n\nLanguage Requirement: ${LANGUAGE_CONTEXT[language]}` : '';

  const agentConfigs = selectedAgents.map(type => AGENTS[type] || AGENTS.coder);

  const agentPromises = agentConfigs.map(async (agent) => {
    const agentStart = Date.now();
    try {
      const enhancedPrompt = agent.prompt + (language ? `\n\nIMPORTANT: ${LANGUAGE_CONTEXT[language]}` : '');
      const response = await callGroq([
        { role: 'system', content: enhancedPrompt },
        { role: 'user', content: task + langContext }
      ], model, 3000);

      return {
        id: `agent-${agent.name.toLowerCase()}`,
        name: agent.name,
        icon: agent.icon,
        role: agent.role,
        status: 'completed',
        response: response.choices[0].message.content,
        latency: Date.now() - agentStart,
        tokens: response.usage?.total_tokens || 0
      };
    } catch (err) {
      return {
        id: `agent-${agent.name.toLowerCase()}`,
        name: agent.name,
        icon: agent.icon,
        role: agent.role,
        status: 'failed',
        error: err.message,
        latency: Date.now() - agentStart
      };
    }
  });

  const agentResults = await Promise.all(agentPromises);

  let synthesis = null;
  if (GROQ_KEY && agentResults.filter(r => r.status === 'completed').length >= 2) {
    const langInstruction = language && LANGUAGE_CONTEXT[language] ? `Language: ${language.toUpperCase()}\n` : '';
    const synthesisPrompt = `You are the Swarm Coordinator. Synthesize the responses from multiple AI agents into a single, coherent, and comprehensive solution.

${langInstruction}Task: ${task}

Agent Results:
${agentResults.filter(r => r.status === 'completed').map(r => `## ${r.name} (${r.icon})\n${r.response}`).join('\n\n')}

Provide:
1. Executive Summary
2. Key Insights (bullet points)
3. Final Solution/Recommendation
4. Implementation Steps (if applicable)
5. Next Steps`;

    const synthesisResponse = await callGroq([
      { role: 'system', content: 'You synthesize complex multi-agent outputs into clear, actionable solutions.' },
      { role: 'user', content: synthesisPrompt }
    ], 'llama-3.3-70b-versatile', 2000);

    synthesis = synthesisResponse.choices[0].message.content;
  }

  const completedCount = agentResults.filter(r => r.status === 'completed').length;

  res.json({
    success: true,
    service: 'agentswarm',
    task,
    language: language || 'auto',
    swarm: agentResults.map(r => ({
      id: r.id,
      name: r.name,
      icon: r.icon,
      role: r.role,
      status: r.status
    })),
    results: agentResults.map(r => ({
      id: r.id,
      name: r.name,
      icon: r.icon,
      status: r.status,
      response: r.response,
      error: r.error,
      latency: r.latency
    })),
    synthesis,
    stats: {
      agentsDeployed: selectedAgents.length,
      agentsCompleted: completedCount,
      agentsFailed: selectedAgents.length - completedCount,
      totalLatency: Date.now() - startTime,
      totalTokens: agentResults.reduce((sum, r) => sum + (r.tokens || 0), 0),
      avgLatency: Math.round(agentResults.reduce((sum, r) => sum + (r.latency || 0), 0) / agentResults.length)
    },
    timestamp: new Date().toISOString()
  });
}

async function handleOrchestrate(res, { task, services, model }) {
  if (!task) return res.status(400).json({ error: 'Task required' });

  const pipeline = services || ['cogi', 'guardian', 'testpilot'];
  const startTime = Date.now();
  const results = [];
  let currentOutput = task;

  const pipelineDescriptions = {
    cogi: 'Generating code...',
    guardian: 'Analyzing security...',
    docufy: 'Creating documentation...',
    testpilot: 'Writing tests...',
    optimizer: 'Optimizing performance...',
    docs: 'Generating docs...'
  };

  for (const service of pipeline) {
    const stepStart = Date.now();

    try {
      let stepResult;

      switch (service) {
        case 'cogi':
          const code = await callGroq([
            { role: 'system', content: SYSTEM_PROMPTS.cogi },
            { role: 'user', content: currentOutput }
          ], model, 4096);
          stepResult = { code: code.choices[0].message.content, tokens: code.usage?.total_tokens };
          currentOutput = code.choices[0].message.content;
          break;

        case 'guardian':
          const security = await callGroq([
            { role: 'system', content: SYSTEM_PROMPTS.guardian },
            { role: 'user', content: `Security analysis:\n\n${currentOutput.slice(0, 2000)}` }
          ], model, 2000);
          const scan = scanPatterns(currentOutput);
          stepResult = { 
            analysis: security.choices[0].message.content,
            score: calculateSecurityScore(scan),
            vulnerabilities: scan.length
          };
          break;

        case 'testpilot':
          const tests = await callGroq([
            { role: 'system', content: SYSTEM_PROMPTS.testpilot },
            { role: 'user', content: `Generate tests for:\n\n${currentOutput.slice(0, 2000)}` }
          ], model, 3000);
          stepResult = { tests: tests.choices[0].message.content };
          break;

        case 'docufy':
          const docs = await callGroq([
            { role: 'system', content: SYSTEM_PROMPTS.docufy },
            { role: 'user', content: `Document this code:\n\n${currentOutput.slice(0, 3000)}` }
          ], model, 3000);
          stepResult = { documentation: docs.choices[0].message.content };
          break;

        default:
          stepResult = { note: `Service ${service} not recognized in pipeline` };
      }

      results.push({
        step: pipeline.indexOf(service) + 1,
        service,
        status: 'success',
        duration: Date.now() - stepStart,
        ...stepResult
      });
    } catch (err) {
      results.push({
        step: pipeline.indexOf(service) + 1,
        service,
        status: 'failed',
        error: err.message,
        duration: Date.now() - stepStart
      });
    }
  }

  res.json({
    success: true,
    service: 'orchestrate',
    task,
    pipeline,
    pipelineDescriptions: pipelineDescriptions,
    results,
    finalOutput: currentOutput,
    stats: {
      totalSteps: pipeline.length,
      completedSteps: results.filter(r => r.status === 'success').length,
      failedSteps: results.filter(r => r.status === 'failed').length,
      totalDuration: Date.now() - startTime
    },
    timestamp: new Date().toISOString()
  });
}

async function handleChat(res, { message, context }) {
  if (!message) return res.status(400).json({ error: 'Message required' });

  const data = await callGroq([
    { role: 'system', content: 'You are Parallax AI, a helpful assistant for developers. You can help with coding, debugging, security, architecture, and general questions. Be concise, helpful, and technical.' },
    { role: 'user', content: context ? `${context}\n\nUser: ${message}` : message }
  ], 'llama-3.3-70b-versatile', 2048);

  res.json({
    success: true,
    service: 'chat',
    response: data.choices[0].message.content,
    model: 'llama-3.3-70b-versatile',
    tokens: data.usage?.total_tokens || 0,
    timestamp: new Date().toISOString()
  });
}
