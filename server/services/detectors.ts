export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export type Category =
  | 'sql_concat'
  | 'hardcoded_secret'
  | 'log_sensitive'
  | 'cors_wildcard'
  | 'caret_range'
  | 'code_execution'
  | 'unsafe_dom';

interface Rule {
  id: string;
  category: Category;
  severity: Severity;
  title: string;
  impact: string;
  remediation: string;
  pattern: RegExp;
  appliesTo?: (filename: string) => boolean;
}

export interface Detection {
  ruleId: string;
  category: Category;
  severity: Severity;
  title: string;
  impact: string;
  remediation: string;
  lines: number[];
  snippet: string;
}

const SOURCE_EXTENSIONS =
  /\.(?:js|jsx|ts|tsx|mts|cts|mjs|cjs|py|java|php|rb|go|cs|sql)$/i;

const WEB_EXTENSIONS = /\.(?:js|jsx|ts|tsx|mts|cts|mjs|cjs|html|vue|svelte)$/i;

const RULES: Rule[] = [
  {
    id: 'sql-concat',
    category: 'sql_concat',
    severity: 'HIGH',
    title: 'Potential SQL query string concatenation',
    impact:
      'Constructing SQL queries with untrusted input may allow SQL injection. The actual risk depends on how the query and its parameters are used.',
    remediation:
      'Use parameterized queries or prepared statements. Bind user input separately instead of concatenating it into SQL.',
    pattern:
      /(?:\b(?:SELECT\b[\s\S]{0,250}?\bFROM\b|INSERT\s+INTO\b[\s\S]{0,250}?|UPDATE\s+\w+\s+SET\b[\s\S]{0,250}?|DELETE\s+FROM\b[\s\S]{0,250}?)[\s\S]{0,200}?(?:['"`]\s*\+\s*[A-Za-z_$][\w$]*|[A-Za-z_$][\w$]*\s*\+\s*['"`])|(?:\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^;\r\n]{0,200}?\$\{[^}]+\}))/gi,
    appliesTo: (filename) => SOURCE_EXTENSIONS.test(filename),
  },
  {
    id: 'hardcoded-secret',
    category: 'hardcoded_secret',
    severity: 'HIGH',
    title: 'Potential hardcoded credential',
    impact:
      'A real credential embedded in source code may be exposed to anyone who can access the code or repository. Placeholder values can also trigger this heuristic.',
    remediation:
      'Store real credentials in environment variables or a secrets manager. Rotate any credential that has been exposed. Verify whether the detected value is a real secret.',
    pattern:
      /\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)\b\s*[:=]\s*(['"`])(?!\s*(?:your[_ -]|replace[_ -]|example|placeholder|changeme|process\.env|import\.meta\.env)\b)[^'"`\r\n]{4,}\1/gi,
    appliesTo: (filename) => SOURCE_EXTENSIONS.test(filename),
  },
  {
    id: 'unsafe-eval',
    category: 'code_execution',
    severity: 'HIGH',
    title: 'Potential dynamic code or command execution',
    impact:
      'Dynamic code evaluation and command execution can be dangerous when arguments contain untrusted input. A match alone does not prove arbitrary code execution.',
    remediation:
      'Avoid evaluating dynamically constructed code. Prefer safe APIs, validate untrusted input, and use fixed executable names and argument arrays when invoking processes.',
    pattern:
      /(?<![\w$.])eval\s*\(|\bnew\s+Function\s*\(|(?<![\w$.])(?:exec|execSync)\s*\(/gi,
    appliesTo: (filename) => SOURCE_EXTENSIONS.test(filename),
  },
  {
    id: 'unsafe-dom-injection',
    category: 'unsafe_dom',
    severity: 'HIGH',
    title: 'Potential unsafe HTML injection',
    impact:
      'Rendering attacker-controlled HTML can enable cross-site scripting (XSS). The risk depends on the source and sanitization of the HTML.',
    remediation:
      'Prefer textContent or framework-safe rendering. If HTML rendering is required, sanitize untrusted HTML with a maintained sanitizer.',
    pattern: /\.innerHTML\s*=|dangerouslySetInnerHTML/gi,
    appliesTo: (filename) => WEB_EXTENSIONS.test(filename),
  },
  {
    id: 'log-query',
    category: 'log_sensitive',
    severity: 'MEDIUM',
    title: 'Potential SQL query logging',
    impact:
      'Logging SQL queries or query variables may expose query structure or sensitive values.',
    remediation:
      'Avoid logging complete queries or their parameters. Log safe diagnostic metadata instead.',
    pattern:
      /\bconsole\s*\.\s*(?:log|error|warn|info|debug)\s*\(\s*(?:query|sql)\s*\)/gi,
    appliesTo: (filename) => SOURCE_EXTENSIONS.test(filename),
  },
  {
    id: 'log-credential',
    category: 'log_sensitive',
    severity: 'MEDIUM',
    title: 'Potential sensitive value written to logs',
    impact:
      'Logging credentials or tokens may expose them to people or systems with access to application logs.',
    remediation:
      'Remove credentials from log messages and redact sensitive values before logging.',
    pattern:
      /\bconsole\s*\.\s*(?:log|error|warn|info|debug)\s*\(\s*(?:(?:"[^"\r\n]*"|'[^'\r\n]*'|`[^`\r\n]*`)\s*,\s*)?(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|resetToken|verificationToken)\b/gi,
    appliesTo: (filename) => SOURCE_EXTENSIONS.test(filename),
  },
  {
    id: 'log-user-object',
    category: 'log_sensitive',
    severity: 'MEDIUM',
    title: 'Potential sensitive user object written to logs',
    impact:
      'Logging complete user or account objects may expose personal information, password hashes, tokens, or other sensitive fields, depending on the object contents.',
    remediation:
      'Avoid logging complete user or account objects. Log only explicitly approved, non-sensitive fields required for debugging.',
    pattern:
      /\bconsole\s*\.\s*(?:log|error|warn|info|debug)\s*\([^)\r\n]{0,200}(?:\buser\b\s*[,)]|\b(?:account|profile)\b\s*[,)]|\b(?:user|account|profile)\s*[,)]\s*[A-Za-z_$][\w$]*\b)/gi,
    appliesTo: (filename) => SOURCE_EXTENSIONS.test(filename),
  },
  {
    id: 'cors-wildcard',
    category: 'cors_wildcard',
    severity: 'LOW',
    title: 'Potentially permissive CORS configuration',
    impact:
      'A permissive cross-origin policy may expose API responses to untrusted websites, depending on authentication and browser credential settings.',
    remediation:
      'Configure an explicit allowlist of trusted origins where appropriate. Review credential settings and actual API exposure.',
    pattern: /\bcors\s*\(\s*\)|\borigin\s*:\s*['"`]\*['"`]/gi,
    appliesTo: (filename) => SOURCE_EXTENSIONS.test(filename),
  },
  {
    id: 'caret-range',
    category: 'caret_range',
    severity: 'LOW',
    title: 'Caret dependency version range',
    impact:
      'Caret ranges permit compatible dependency updates, so installations may resolve to different versions over time. A caret range alone is not proof of a vulnerable dependency.',
    remediation:
      'Commit and maintain a lockfile, audit dependencies regularly, and pin versions where required by policy.',
    pattern: /"[^"\r\n]+"\s*:\s*"\^\d[^"\r\n]*"/g,
    appliesTo: (filename) =>
      /(^|\/)package\.json$/i.test(filename.replace(/\\/g, '/')),
  },
];

const RANK: Record<Severity, number> = {
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

const SUPPRESS = /^devpulse-ignore(?:\s+([a-z][\w-]*))?\s*$/i;

function getLineNumber(content: string, index: number): number {
  let lineNumber = 1;

  for (let i = 0; i < index; i += 1) {
    if (content.charCodeAt(i) === 10) {
      lineNumber += 1;
    }
  }

  return lineNumber;
}

function getLineComment(line: string): string | null {
  const commentMatch = /(?:^|\s)\/\/(.*)$/.exec(line);
  return commentMatch?.[1]?.trim() ?? null;
}

function isSuppressed(line: string, ruleId: string): boolean {
  const comment = getLineComment(line);

  if (!comment) {
    return false;
  }

  const match = SUPPRESS.exec(comment);

  if (!match) {
    return false;
  }

  const requestedRule = match[1]?.toLowerCase();

  return !requestedRule || requestedRule === ruleId;
}

export function runDetectors(filename: string, content: string): Detection[] {
  const lines = content.split(/\r?\n/);
  const detections: Detection[] = [];

  for (const rule of RULES) {
    if (rule.appliesTo && !rule.appliesTo(filename)) {
      continue;
    }

    const hits = new Map<number, string>();

    const pattern = new RegExp(rule.pattern.source, rule.pattern.flags);

    for (const match of content.matchAll(pattern)) {
      if (match.index === undefined || !match[0]) {
        continue;
      }

      const start = match.index;
      const end = start + match[0].length;
      const startLine = getLineNumber(content, start);
      const endLine = getLineNumber(content, Math.max(start, end - 1));
      const sourceLine = lines[startLine - 1] ?? '';

      const isRegexDefinition =
        /^\s*(?:(?:const|let|var)\s+\w+\s*=\s*|pattern\s*:\s*)\/.*\/[dgimsuvy]*\s*[,;]?\s*$/.test(
          sourceLine,
        );

      if (rule.id === 'unsafe-dom-injection' && isRegexDefinition) {
        continue;
      }

      if (isSuppressed(sourceLine, rule.id)) {
        continue;
      }

      if (!hits.has(startLine)) {
        const evidence = lines
          .slice(startLine - 1, Math.min(endLine, startLine + 2))
          .join(' ')
          .trim();

        hits.set(startLine, evidence || sourceLine.trim());
      }
    }

    if (hits.size === 0) {
      continue;
    }

    const entries = [...hits.entries()];

    detections.push({
      ruleId: rule.id,
      category: rule.category,
      severity: rule.severity,
      title: rule.title,
      impact: rule.impact,
      remediation: rule.remediation,
      lines: entries.map(([lineNumber]) => lineNumber),
      snippet: entries[0][1].replace(/`/g, "'").slice(0, 160),
    });
  }

  return detections;
}

export function maxSeverity(detections: Detection[]): Severity | null {
  return detections.reduce<Severity | null>(
    (best, detection) =>
      best === null || RANK[detection.severity] > RANK[best]
        ? detection.severity
        : best,
    null,
  );
}

export function buildFindingsReport(
  filename: string,
  detections: Detection[],
  isTruncated = false,
): string {
  const findings = detections.map((detection, index) => {
    const shown = detection.lines.slice(0, 5).join(', ');
    const extra =
      detection.lines.length > 5
        ? ` (+${detection.lines.length - 5} more)`
        : '';

    const where = detection.lines.length === 1 ? 'line' : 'lines';

    return `### Finding ${index + 1}: ${detection.title}

- **Severity:** ${detection.severity}
- **Category:** ${detection.category}
- **Location:** ${where} ${shown}${extra}
- **Evidence:** \`${detection.snippet}\`
- **Security impact:** ${detection.impact}
- **Recommended remediation:** ${detection.remediation}`;
  });

  const actions = [
    ...new Set(detections.map((detection) => detection.remediation)),
  ]
    .map((remediation) => `- ${remediation}`)
    .join('\n');

  const count = detections.length;

  const truncationNotice = isTruncated
    ? '\n\n> **Notice:** This file exceeded the 30,000-character limit. Analysis was performed on truncated content.'
    : '';

  return `# Security Report

## Executive Summary

${count} potential ${
    count === 1 ? 'finding was' : 'findings were'
  } detected in \`${filename}\` by static code-pattern rules. Findings require contextual validation.${truncationNotice}

## Findings

${findings.join('\n\n')}

## Recommended Actions

${actions || '- No specific remediation actions were generated.'}`;
}
