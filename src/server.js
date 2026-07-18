import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

// __MCP_VERSION__ is replaced at build time by esbuild define
const VERSION = typeof __MCP_VERSION__ !== 'undefined' ? __MCP_VERSION__ : '0.0.0';
const USER_AGENT = `Shieldly-MCP/${VERSION}`;

const DEFAULT_API = 'https://api.shieldly.io';
const DEFAULT_WEB = 'https://www.shieldly.io';

function getApiBase() {
  return (process.env.SHIELDLY_API_URL || DEFAULT_API).replace(/\/$/, '');
}

function getWebBase() {
  return (process.env.SHIELDLY_WEB_URL || DEFAULT_WEB).replace(/\/$/, '');
}

function getApiKey() {
  return process.env.SHIELDLY_API_KEY || null;
}

// Authenticated analyze calls can return a 202 + jobId for async processing;
// poll until the job completes rather than surfacing an incomplete result.
async function pollJob(jobId, apiKey) {
  const delays = [2000, 3000, 5000];
  for (let i = 0; i < 180; i++) {
    const delay = delays[Math.min(i, delays.length - 1)];
    await new Promise((r) => setTimeout(r, delay));
    const res = await fetch(`${getApiBase()}/v1/jobs/${encodeURIComponent(jobId)}`, {
      headers: { Authorization: `Bearer ${apiKey}`, 'User-Agent': USER_AGENT },
    });
    if (!res.ok) continue;
    const data = await res.json();
    if (data.status === 'complete') return { ...data.result, unitInfo: data.unitInfo };
    if (data.status === 'failed') throw new Error(data.error || 'Analysis failed');
  }
  throw new Error('Analysis timed out after polling');
}

async function apiPost(path, body, apiKey) {
  const res = await fetch(`${getApiBase()}${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': USER_AGENT,
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify(body),
  });
  if (res.status === 202) {
    const data = await res.json().catch(() => ({}));
    if (data.jobId) return pollJob(data.jobId, apiKey);
    throw new Error('Analysis queued but no job ID returned — try again');
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || `API error ${res.status}`);
  }
  return res.json();
}

// Unauthenticated demo path — same non-browser demo proxy the CLI and VS Code
// extension use (ADR-016). Rate-limited per IP + a global daily budget on the
// server side; no client-side identification is required.
async function apiPostDemo(path, body) {
  const res = await fetch(`${getWebBase()}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'User-Agent': USER_AGENT },
    body: JSON.stringify(body),
  });
  if (res.status === 429) {
    throw new Error(
      'Demo rate limit reached. Get an API key (Builder plan or above) for higher limits: https://www.shieldly.io/app/api'
    );
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || `API error ${res.status}`);
  }
  return res.json();
}

function formatResult(data) {
  const lines = [];
  const scoreStr = data.score === null || data.score === undefined ? '—' : `${data.score}/100`;
  lines.push(`AI-Powered Security Analysis — Shieldly`);
  lines.push(`Security Score: ${scoreStr}`);
  lines.push(`Risk Level: ${data.riskLevel || 'Unknown'}`);
  if (data.cached) lines.push('(cached result)');
  if (data.summary) lines.push(`\n${data.summary}`);

  const findings = data.findings || [];
  if (findings.length === 0) {
    lines.push('\nNo findings.');
  } else {
    lines.push(`\nFindings (${findings.length}):`);
    for (const f of findings) {
      lines.push(`\n[${f.severity}] ${f.title}`);
      if (f.resource && f.resource !== '*') lines.push(`  Resource: ${f.resource}`);
      if (f.description) lines.push(`  ${f.description}`);
      if (f.remediation) lines.push(`  Fix: ${f.remediation}`);
    }
  }

  if (!getApiKey() && data.demoInfo?.analysesRemaining !== undefined) {
    lines.push(
      `\nDemo analyses remaining: ${data.demoInfo.analysesRemaining}. Get an API key (Builder plan or above) for more: https://www.shieldly.io/app/api`
    );
  }
  return lines.join('\n');
}

const server = new McpServer(
  { name: 'shieldly', version: VERSION },
  { capabilities: { tools: {} } }
);

server.registerTool(
  'analyze_iam_policy',
  {
    title: 'Analyze AWS IAM Policy',
    description:
      'AI-Powered security analysis of an AWS IAM policy (identity policy or cross-account trust+identity pair). ' +
      'Flags privilege-escalation paths, wildcards, and other over-permissive access. Runs in demo mode ' +
      '(rate-limited, no signup) if SHIELDLY_API_KEY is not set.',
    inputSchema: {
      policy: z
        .string()
        .describe(
          'The IAM policy JSON as a string. For cross_account, a JSON object with identityPolicy and trustPolicy.'
        ),
      policyType: z
        .enum(['identity', 'cross_account'])
        .default('identity')
        .describe('identity (default) for a normal IAM/resource policy, or cross_account.'),
    },
  },
  async ({ policy, policyType }) => {
    try {
      JSON.parse(policy);
    } catch {
      return {
        isError: true,
        content: [{ type: 'text', text: 'Error: policy must be valid JSON.' }],
      };
    }
    const normalizedType = policyType === 'cross_account' ? 'cross_account' : 'iam_identity';
    const apiKey = getApiKey();
    try {
      const data = apiKey
        ? await apiPost('/v1/analyze/iam', { policy, policyType: normalizedType }, apiKey)
        : await apiPostDemo('/api/demo/analyze-iam', { policy, policyType: normalizedType });
      return { content: [{ type: 'text', text: formatResult(data) }] };
    } catch (err) {
      return { isError: true, content: [{ type: 'text', text: `Error: ${err.message}` }] };
    }
  }
);

server.registerTool(
  'analyze_cloudformation_template',
  {
    title: 'Analyze CloudFormation Template',
    description:
      'AI-Powered security analysis of a CloudFormation template — extracts IAM roles/policies and flags ' +
      'over-permissive access. Runs in demo mode (rate-limited, no signup) if SHIELDLY_API_KEY is not set.',
    inputSchema: {
      template: z.string().describe('The CloudFormation template JSON as a string.'),
    },
  },
  async ({ template }) => {
    try {
      JSON.parse(template);
    } catch {
      return {
        isError: true,
        content: [{ type: 'text', text: 'Error: template must be valid JSON.' }],
      };
    }
    const apiKey = getApiKey();
    try {
      const data = apiKey
        ? await apiPost('/v1/analyze/cf', { template }, apiKey)
        : await apiPostDemo('/api/demo/analyze-iam', { template, policyType: 'cf' });
      return { content: [{ type: 'text', text: formatResult(data) }] };
    } catch (err) {
      return { isError: true, content: [{ type: 'text', text: `Error: ${err.message}` }] };
    }
  }
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error('Shieldly MCP server failed to start:', err);
  process.exit(1);
});
