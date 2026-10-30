import {
  Router,
  type Request,
  type Response as ExpressResponse,
} from 'express';
import { analyzeRepository, type RepositoryFile } from '../services/analyzer';

const router = Router();

const MAX_FILES = 500;
const MAX_FILE_CHARACTERS = 200_000;
const MAX_PACKAGE_LOCK_CHARACTERS = 5_000_000;
const MAX_TOTAL_CHARACTERS = 12_000_000;

const REQUEST_TIMEOUT_MS = 15_000;
const FILE_TIMEOUT_MS = 20_000;
const FETCH_CONCURRENCY = 8;

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
  'requirements.txt',
  'pipfile',
  'pom.xml',
  'build.gradle',
]);

interface GithubRepository {
  default_branch?: string;
}

interface GithubTreeItem {
  path: string;
  type: string;
}

interface GithubTreeResponse {
  tree?: GithubTreeItem[];
  truncated?: boolean;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function normalizePath(value: string): string {
  return value.replace(/\\/g, '/').replace(/^\.\/+/, '');
}

function shouldIncludeFile(filename: string): boolean {
  const normalized = normalizePath(filename).toLowerCase();
  const segments = normalized.split('/').filter(Boolean);
  const basename = segments[segments.length - 1] ?? '';

  if (!basename) return false;

  if (
    normalized.startsWith('/') ||
    /^[a-z]:/i.test(normalized) ||
    segments.some(
      (segment) =>
        segment === '.' || segment === '..' || IGNORED_DIRECTORIES.has(segment),
    )
  ) {
    return false;
  }

  if (
    SENSITIVE_FILE_PATTERNS.some((pattern) => pattern.test(basename)) ||
    IGNORED_EXTENSIONS.some((extension) => basename.endsWith(extension))
  ) {
    return false;
  }

  return (
    SUPPORTED_FILENAMES.has(basename) ||
    ANALYZABLE_EXTENSIONS.some((extension) => basename.endsWith(extension))
  );
}

function getFileCharacterLimit(filename: string): number {
  return /(^|\/)package-lock\.json$/i.test(filename)
    ? MAX_PACKAGE_LOCK_CHARACTERS
    : MAX_FILE_CHARACTERS;
}

function validateRepositoryFiles(files: unknown[]): RepositoryFile[] {
  if (files.length === 0) {
    throw new Error('Repository contains no files to analyze.');
  }

  if (files.length > MAX_FILES) {
    throw new Error(`A maximum of ${MAX_FILES} files can be analyzed.`);
  }

  const validatedFiles: RepositoryFile[] = [];
  let totalCharacters = 0;

  for (const file of files) {
    if (!isRecord(file)) {
      throw new Error('Invalid repository file payload.');
    }

    const { name, content } = file;

    if (
      typeof name !== 'string' ||
      !name.trim() ||
      typeof content !== 'string'
    ) {
      throw new Error('Invalid repository file name or content.');
    }

    const normalizedName = normalizePath(name);

    if (
      normalizedName.includes('\0') ||
      normalizedName.startsWith('/') ||
      /^[a-z]:/i.test(normalizedName) ||
      normalizedName
        .split('/')
        .some((segment) => segment === '.' || segment === '..')
    ) {
      throw new Error('Invalid repository file path.');
    }

    if (!shouldIncludeFile(normalizedName)) {
      continue;
    }

    const maxCharacters = getFileCharacterLimit(normalizedName);

    if (content.length > maxCharacters) {
      throw new Error(
        `${normalizedName} exceeds its ${maxCharacters.toLocaleString()}-character limit.`,
      );
    }

    totalCharacters += content.length;

    if (totalCharacters > MAX_TOTAL_CHARACTERS) {
      throw new Error(
        'Repository exceeds the 12,000,000-character total limit.',
      );
    }

    validatedFiles.push({
      name: normalizedName,
      content,
    });
  }

  if (validatedFiles.length === 0) {
    throw new Error('No supported repository files were found.');
  }

  return validatedFiles;
}

async function githubFetch(
  url: string,
  timeoutMs = REQUEST_TIMEOUT_MS,
): Promise<globalThis.Response> {
  const response = await fetch(url, {
    headers: {
      Accept: 'application/vnd.github+json',
      'User-Agent': 'DevPulse-AI-Scanner',
      'X-GitHub-Api-Version': '2022-11-28',
    },
    signal: AbortSignal.timeout(timeoutMs),
  });

  if (response.status === 403 || response.status === 429) {
    throw new Error(
      'GitHub API rate limit reached. Please wait and try again.',
    );
  }

  return response;
}

async function fetchGithubFile(
  owner: string,
  repo: string,
  branch: string,
  filePath: string,
): Promise<RepositoryFile> {
  const encodedBranch = branch.split('/').map(encodeURIComponent).join('/');

  const encodedPath = filePath.split('/').map(encodeURIComponent).join('/');

  const rawUrl =
    `https://raw.githubusercontent.com/${owner}/${repo}/` +
    `${encodedBranch}/${encodedPath}`;

  const response = await fetch(rawUrl, {
    headers: {
      'User-Agent': 'DevPulse-AI-Scanner',
    },
    signal: AbortSignal.timeout(FILE_TIMEOUT_MS),
  });

  if (!response.ok) {
    throw new Error(
      `Unable to download ${filePath} from GitHub (HTTP ${response.status}).`,
    );
  }

  const content = await response.text();
  const maxCharacters = getFileCharacterLimit(filePath);

  if (content.length > maxCharacters) {
    throw new Error(
      `${filePath} exceeds its ${maxCharacters.toLocaleString()}-character limit.`,
    );
  }

  return {
    name: filePath,
    content,
  };
}

async function fetchFilesFromTree(
  owner: string,
  repo: string,
  branch: string,
  treeData: GithubTreeResponse,
): Promise<RepositoryFile[]> {
  if (!Array.isArray(treeData.tree)) {
    throw new Error('Invalid repository tree received from GitHub.');
  }

  if (treeData.truncated) {
    throw new Error(
      'GitHub returned an incomplete repository tree. This repository is too large for a complete scan.',
    );
  }

  const filePaths = treeData.tree
    .filter(
      (node) =>
        node.type === 'blob' &&
        typeof node.path === 'string' &&
        shouldIncludeFile(node.path),
    )
    .map((node) => normalizePath(node.path));

  if (filePaths.length === 0) {
    throw new Error('No supported source files were found in this repository.');
  }

  if (filePaths.length > MAX_FILES) {
    throw new Error(
      `Repository contains ${filePaths.length} supported files. The maximum supported limit is ${MAX_FILES}.`,
    );
  }

  const files: RepositoryFile[] = [];
  let totalCharacters = 0;

  for (let start = 0; start < filePaths.length; start += FETCH_CONCURRENCY) {
    const batch = filePaths.slice(start, start + FETCH_CONCURRENCY);

    const batchResults = await Promise.all(
      batch.map((filePath) => fetchGithubFile(owner, repo, branch, filePath)),
    );

    for (const file of batchResults) {
      totalCharacters += file.content.length;

      if (totalCharacters > MAX_TOTAL_CHARACTERS) {
        throw new Error(
          'Repository exceeds the 12,000,000-character total limit.',
        );
      }

      files.push(file);
    }
  }

  return validateRepositoryFiles(files);
}

async function fetchGithubRepoFiles(
  githubUrl: string,
): Promise<RepositoryFile[]> {
  let parsedUrl: URL;

  try {
    parsedUrl = new URL(githubUrl);
  } catch {
    throw new Error('Enter a valid GitHub repository URL.');
  }

  if (
    parsedUrl.protocol !== 'https:' ||
    parsedUrl.hostname !== 'github.com' ||
    parsedUrl.port ||
    parsedUrl.username ||
    parsedUrl.password ||
    parsedUrl.search ||
    parsedUrl.hash
  ) {
    throw new Error('Only valid public GitHub repository URLs are supported.');
  }

  const match = parsedUrl.pathname.match(
    /^\/([A-Za-z0-9-]+)\/([A-Za-z0-9_.-]+)\/?$/,
  );

  if (!match) {
    throw new Error('Use this format: https://github.com/owner/repository');
  }

  const [, owner, repo] = match;

  const repositoryResponse = await githubFetch(
    `https://api.github.com/repos/${owner}/${repo}`,
  );

  if (repositoryResponse.status === 404) {
    throw new Error(
      'Repository not found or it is private. Only public repositories are supported.',
    );
  }

  if (!repositoryResponse.ok) {
    throw new Error(
      `GitHub repository lookup failed (HTTP ${repositoryResponse.status}).`,
    );
  }

  const repositoryData = (await repositoryResponse.json()) as GithubRepository;

  const defaultBranch = repositoryData.default_branch;

  if (!defaultBranch) {
    throw new Error('Unable to determine the repository default branch.');
  }

  const treeResponse = await githubFetch(
    `https://api.github.com/repos/${owner}/${repo}/git/trees/${encodeURIComponent(defaultBranch)}?recursive=1`,
  );

  if (!treeResponse.ok) {
    throw new Error(
      `Unable to fetch repository structure from GitHub (HTTP ${treeResponse.status}).`,
    );
  }

  const treeData = (await treeResponse.json()) as GithubTreeResponse;

  return fetchFilesFromTree(owner, repo, defaultBranch, treeData);
}

router.post('/', async (req: Request, res: ExpressResponse) => {
  try {
    const body: unknown = req.body;

    if (!isRecord(body)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid request payload format.',
      });
    }

    let repositoryFiles: RepositoryFile[];

    if ('githubUrl' in body) {
      if (typeof body.githubUrl !== 'string' || !body.githubUrl.trim()) {
        return res.status(400).json({
          success: false,
          message: 'A valid GitHub repository URL is required.',
        });
      }

      repositoryFiles = await fetchGithubRepoFiles(body.githubUrl.trim());
    } else if ('files' in body && Array.isArray(body.files)) {
      repositoryFiles = validateRepositoryFiles(body.files);
    } else {
      return res.status(400).json({
        success: false,
        message: 'No valid repository files or GitHub URL were provided.',
      });
    }

    const result = await analyzeRepository(repositoryFiles);

    return res.status(result.success ? 200 : 400).json(result);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';

    console.error('[DevPulse] Repository analysis request failed:', message);

    return res.status(400).json({
      success: false,
      message: message || 'Repository analysis failed. Please try again.',
    });
  }
});

export default router;
