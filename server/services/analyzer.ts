import { researchSecurityIssue } from './tavily';
import { explainFindings } from './nebius';
import {
  runDetectors,
  maxSeverity,
  buildFindingsReport,
  type Detection,
  type Severity,
} from './detectors';

export type { Severity } from './detectors';

export interface RepositoryFile {
  name: string;
  content: string;
}

export interface FileAnalysis {
  filename: string;
  analysis: string;
  severity: Severity | 'REVIEW';
  research?: {
    query: string;
    answer: string;
    sources: Array<{
      title: string;
      url: string;
    }>;
  };
}

export interface RepositoryAnalysis {
  success: boolean;
  filesAnalyzed: number;
  results: FileAnalysis[];
}

const MAX_FILES = 20;
const MAX_FILE_SIZE = 30_000;
const ANALYSIS_CONCURRENCY = 4;

const IGNORED_DIRECTORIES = new Set([
  'node_modules',
  '.git',
  '.idea',
  'dist',
  'build',
  'coverage',
  '.next',
  '.venv',
  'venv',
]);

const IGNORED_EXTENSIONS = [
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.webp',
  '.ico',
  '.pdf',
  '.zip',
  '.rar',
  '.7z',
  '.mp4',
  '.mp3',
  '.wav',
  '.woff',
  '.woff2',
  '.ttf',
  '.eot',
  '.svg',
  '.lock',
];

const SENSITIVE_FILE_PATTERNS = [
  /^\.env(?:\.|$)/i,
  /\.(?:pem|key|p12|pfx)$/i,
  /^id_(?:rsa|dsa|ecdsa|ed25519)$/i,
  /^(?:credentials|secrets?)(?:\..*)?$/i,
];

const ANALYZABLE_EXTENSIONS = [
  '.js',
  '.jsx',
  '.ts',
  '.tsx',
  '.mjs',
  '.cjs',
  '.mts',
  '.cts',
  '.py',
  '.java',
  '.go',
  '.rs',
  '.php',
  '.rb',
  '.c',
  '.cpp',
  '.cc',
  '.h',
  '.hpp',
  '.cs',
  '.swift',
  '.kt',
  '.kts',
  '.scala',
  '.sql',
  '.html',
  '.htm',
  '.css',
  '.scss',
  '.sass',
  '.vue',
  '.svelte',
  '.xml',
  '.yaml',
  '.yml',
  '.json',
  '.toml',
  '.sh',
  '.bash',
  '.zsh',
  '.ps1',
  '.graphql',
  '.gql',
  '.md',
  '.txt',
];

const SUPPORTED_FILENAMES = new Set([
  'dockerfile',
  'makefile',
  'jenkinsfile',
  'procfile',
  'gemfile',
  'rakefile',
  '.gitignore',
  '.dockerignore',
  '.npmrc',
  '.nvmrc',
  '.prettierrc',
  '.eslintrc',
  'package.json',
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'requirements.txt',
  'pipfile',
  'pom.xml',
  'build.gradle',
]);

function normalizePath(path: string): string {
  return path.replace(/\\/g, '/').replace(/^\.\/+/, '');
}

function shouldAnalyzeFile(filename: string): boolean {
  const normalizedPath = normalizePath(filename).toLowerCase();
  const segments = normalizedPath.split('/').filter(Boolean);
  const basename = segments[segments.length - 1] ?? '';

  if (!basename) {
    return false;
  }

  if (segments.some((segment) => IGNORED_DIRECTORIES.has(segment))) {
    return false;
  }

  if (SENSITIVE_FILE_PATTERNS.some((pattern) => pattern.test(basename))) {
    return false;
  }

  if (IGNORED_EXTENSIONS.some((extension) => basename.endsWith(extension))) {
    return false;
  }

  if (SUPPORTED_FILENAMES.has(basename)) {
    return true;
  }

  return ANALYZABLE_EXTENSIONS.some((extension) =>
    basename.endsWith(extension),
  );
}

function limitFileContent(content: string): {
  content: string;
  isTruncated: boolean;
} {
  if (content.length <= MAX_FILE_SIZE) {
    return { content, isTruncated: false };
  }

  return {
    content: content.slice(0, MAX_FILE_SIZE),
    isTruncated: true,
  };
}

function buildCleanReport(filename: string, isTruncated = false): string {
  const truncationNotice = isTruncated
    ? '\n\n> **Notice:** This file exceeded the 30,000-character limit. Only the initial portion was analyzed.'
    : '';

  return `# Security Report

## Executive Summary

No known vulnerable code pattern was detected in ${filename} by the configured static rules. This does not guarantee that the file is secure.${truncationNotice}

## Findings

### Finding: No detected vulnerabilities

- **Severity:** LOW
- **Evidence:** No configured vulnerable code pattern was detected.
- **Security impact:** No impact was established by this scan.
- **Recommended remediation:** Continue following secure coding practices and review security-sensitive logic manually.

## Recommended Actions

Review authentication, authorization, input validation, dependencies, and other security-sensitive behavior as appropriate.`;
}

function buildFailedReport(): string {
  return `# Security Report

## Executive Summary

Automated analysis could not be completed for this file. Manual review is required.

## Analysis Status

- **Severity:** REVIEW
- **Result:** The scan was unable to produce a reliable analysis.
- **Recommended action:** Retry the scan and review this file manually.`;
}

function buildResearchQuery(filename: string, detections: Detection[]): string {
  const items = detections
    .map((detection) => `- ${detection.title} (${detection.category})`)
    .join('\n');

  return `Research security guidance for the following detected code patterns in ${filename}.

Detected patterns:
${items}

Find relevant official security advisories, CWE or OWASP guidance, and remediation best practices where applicable. Do not invent CVEs or claim a CVE applies without supporting evidence.`;
}

function formatDetectorSummary(detections: Detection[]): string {
  return detections
    .map(
      (detection) =>
        `- ${detection.title} | Category: ${detection.category} | Severity: ${detection.severity} | Lines: ${detection.lines.join(', ')} | Evidence: ${detection.snippet}`,
    )
    .join('\n');
}

function appendAdditionalObservations(
  report: string,
  observations: string,
): string {
  const trimmed = observations.trim();

  if (!trimmed) {
    return report;
  }

  return `${report.trim()}

## Additional Observations

${trimmed}`;
}

async function analyzeFile(file: RepositoryFile): Promise<FileAnalysis> {
  try {
    const { content, isTruncated } = limitFileContent(file.content);
    const detections = runDetectors(file.name, content);

    if (detections.length === 0) {
      return {
        filename: file.name,
        severity: 'LOW',
        analysis: buildCleanReport(file.name, isTruncated),
      };
    }

    const severity = maxSeverity(detections) ?? 'LOW';
    const analysis = buildFindingsReport(file.name, detections, isTruncated);

    const detectorSummary = formatDetectorSummary(detections);

    const [researchResult, explanationResult] = await Promise.allSettled([
      researchSecurityIssue(buildResearchQuery(file.name, detections)),
      explainFindings(file.name, content, detectorSummary),
    ]);

    let research: FileAnalysis['research'];

    if (researchResult.status === 'fulfilled') {
      const result = researchResult.value;

      research = {
        query: result.query,
        answer: result.answer,
        sources: result.sources.map((source) => ({
          title: source.title,
          url: source.url,
        })),
      };
    } else {
      console.error(
        `[DevPulse] Research failed for ${file.name}:`,
        researchResult.reason instanceof Error
          ? researchResult.reason.message
          : researchResult.reason,
      );
    }

    let finalAnalysis = analysis;

    if (explanationResult.status === 'fulfilled') {
      finalAnalysis = appendAdditionalObservations(
        analysis,
        explanationResult.value,
      );
    } else {
      console.error(
        `[DevPulse] Nemotron explanation failed for ${file.name}:`,
        explanationResult.reason instanceof Error
          ? explanationResult.reason.message
          : explanationResult.reason,
      );
    }

    return {
      filename: file.name,
      severity,
      analysis: finalAnalysis,
      ...(research ? { research } : {}),
    };
  } catch (error) {
    console.error(
      `[DevPulse] Analysis failed for ${file.name}:`,
      error instanceof Error ? error.message : error,
    );

    return {
      filename: file.name,
      severity: 'REVIEW',
      analysis: buildFailedReport(),
    };
  }
}

async function runWithConcurrency(
  files: RepositoryFile[],
): Promise<FileAnalysis[]> {
  const results: FileAnalysis[] = [];

  for (let start = 0; start < files.length; start += ANALYSIS_CONCURRENCY) {
    const batch = files.slice(start, start + ANALYSIS_CONCURRENCY);

    const batchResults = await Promise.all(
      batch.map((file) => analyzeFile(file)),
    );

    results.push(...batchResults);
  }

  return results;
}

export async function analyzeRepository(
  files: RepositoryFile[],
): Promise<RepositoryAnalysis> {
  const analyzableFiles = files
    .filter((file) => shouldAnalyzeFile(file.name))
    .slice(0, MAX_FILES);

  if (analyzableFiles.length === 0) {
    return {
      success: false,
      filesAnalyzed: 0,
      results: [],
    };
  }

  const results = await runWithConcurrency(analyzableFiles);

  return {
    success: true,
    filesAnalyzed: results.length,
    results,
  };
}
