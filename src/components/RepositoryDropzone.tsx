import {
  useRef,
  useState,
  type DragEvent,
  type InputHTMLAttributes,
} from 'react';
import type { RepositoryAnalysis } from '../types/security';

export type EngineStatus =
  | 'ENGINE READY'
  | 'ANALYZING REPOSITORY'
  | 'RESEARCHING SECURITY INTELLIGENCE'
  | 'GENERATING REPORT'
  | 'SCAN COMPLETE';

interface RepositoryDropzoneProps {
  onAnalysisStart?: () => void;
  onStatusChange?: (status: EngineStatus) => void;
  onAnalysisComplete: (result: RepositoryAnalysis) => void;
}

interface SelectedRepositoryFile {
  file: File;
  path: string;
}

interface RepositoryPayloadFile {
  name: string;
  content: string;
}


interface DirectoryEntryLike {
  isFile: boolean;
  isDirectory: boolean;
  name: string;
  file?: (
    success: (file: File) => void,
    error?: (error: DOMException) => void,
  ) => void;
  createReader?: () => {
    readEntries: (
      success: (entries: DirectoryEntryLike[]) => void,
      error?: (error: DOMException) => void,
    ) => void;
  };
}

type DataTransferItemWithEntry = DataTransferItem & {
  webkitGetAsEntry?: () => unknown;
};


const MAX_FILES = 20;
const MAX_FILE_CHARACTERS = 30_000;
const MAX_REQUEST_BYTES = 14 * 1024 * 1024;
const MAX_DIRECTORY_ENTRIES = 5000;

const API_BASE_URL = (
  import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000'
).replace(/\/+$/, '');

const IGNORED_DIRECTORIES = [
  'node_modules',
  '.git',
  '.idea',
  'dist',
  'build',
  'coverage',
  '.next',
  '.venv',
  'venv',
];

const SENSITIVE_FILE_PATTERNS = [
  /^\.env(?:\.|$)/i,
  /\.(?:pem|key|p12|pfx)$/i,
  /^id_(?:rsa|dsa|ecdsa|ed25519)$/i,
  /^(?:credentials|secrets?)(?:\..*)?$/i,
];

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

const SUPPORTED_EXTENSIONS = [
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
  '.cs',
  '.cpp',
  '.cc',
  '.c',
  '.h',
  '.hpp',
  '.html',
  '.htm',
  '.css',
  '.scss',
  '.sass',
  '.json',
  '.yaml',
  '.yml',
  '.toml',
  '.xml',
  '.sql',
  '.sh',
  '.bash',
  '.zsh',
  '.ps1',
  '.vue',
  '.svelte',
  '.graphql',
  '.gql',
  '.md',
  '.txt',
];

const SUPPORTED_FILENAMES = [
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
];

function normalizePath(path: string): string {
  return path.replace(/\\/g, '/').replace(/^\.\/+/, '');
}

function shouldIncludeFile(path: string): boolean {
  const normalizedPath = normalizePath(path);
  const lowerPath = normalizedPath.toLowerCase();
  const segments = lowerPath.split('/').filter(Boolean);
  const filename = segments[segments.length - 1] ?? '';

  if (
    !filename ||
    segments.some((segment) => IGNORED_DIRECTORIES.includes(segment))
  ) {
    return false;
  }

  if (
    SENSITIVE_FILE_PATTERNS.some((pattern) => pattern.test(filename)) ||
    IGNORED_EXTENSIONS.some((extension) => filename.endsWith(extension))
  ) {
    return false;
  }

  return (
    SUPPORTED_FILENAMES.includes(filename) ||
    SUPPORTED_EXTENSIONS.some((extension) => filename.endsWith(extension))
  );
}

function getFilePath(file: File): string {
  const relativePath = (file as File & { webkitRelativePath?: string })
    .webkitRelativePath;

  return normalizePath(relativePath || file.name);
}

function filterRepositoryFiles(
  incomingFiles: FileList | File[],
): SelectedRepositoryFile[] {
  return Array.from(incomingFiles)
    .map((file) => ({
      file,
      path: getFilePath(file),
    }))
    .filter(({ path }) => shouldIncludeFile(path));
}

function readDirectoryEntries(
  directory: DirectoryEntryLike,
): Promise<DirectoryEntryLike[]> {
  return new Promise((resolve, reject) => {
    if (!directory.createReader) {
      reject(new Error('This browser cannot read dropped folders.'));
      return;
    }

    const reader = directory.createReader();
    const allEntries: DirectoryEntryLike[] = [];

    const readBatch = () => {
      reader.readEntries(
        (entries) => {
          if (entries.length === 0) {
            resolve(allEntries);
            return;
          }

          allEntries.push(...entries);

          if (allEntries.length > MAX_DIRECTORY_ENTRIES) {
            reject(
              new Error(
                'This folder contains too many entries. Select a smaller repository subset.',
              ),
            );
            return;
          }

          readBatch();
        },
        () => reject(new Error('Unable to read a dropped folder.')),
      );
    };

    readBatch();
  });
}

function readEntryFile(entry: DirectoryEntryLike): Promise<File> {
  return new Promise((resolve, reject) => {
    if (!entry.file) {
      reject(new Error('Unable to read a dropped file.'));
      return;
    }

    entry.file(resolve, () => {
      reject(new Error('Unable to read a dropped file.'));
    });
  });
}

async function collectEntryFiles(
  entry: DirectoryEntryLike,
  parentPath = '',
  collected: SelectedRepositoryFile[] = [],
  counter = { value: 0 },
): Promise<void> {
  counter.value += 1;

  if (counter.value > MAX_DIRECTORY_ENTRIES) {
    throw new Error(
      'This folder contains too many entries. Select a smaller repository subset.',
    );
  }

  const entryPath = normalizePath(`${parentPath}/${entry.name}`);

  if (entry.isFile) {
    if (shouldIncludeFile(entryPath)) {
      const file = await readEntryFile(entry);

      collected.push({
        file,
        path: entryPath,
      });

      if (collected.length > MAX_FILES) {
        throw new Error(
          `More than ${MAX_FILES} supported files were found. Select a smaller repository subset.`,
        );
      }
    }

    return;
  }

  if (entry.isDirectory) {
    const directorySegments = entryPath.toLowerCase().split('/');

    if (
      directorySegments.some((segment) => IGNORED_DIRECTORIES.includes(segment))
    ) {
      return;
    }

    const entries = await readDirectoryEntries(entry);

    for (const child of entries) {
      await collectEntryFiles(child, entryPath, collected, counter);
    }
  }
}

function RepositoryDropzone({
  onAnalysisStart,
  onStatusChange,
  onAnalysisComplete,
}: RepositoryDropzoneProps) {
  const folderInputRef = useRef<HTMLInputElement>(null);
  const filesInputRef = useRef<HTMLInputElement>(null);
  const dragCounter = useRef(0);

  const [isDragging, setIsDragging] = useState(false);
  const [files, setFiles] = useState<SelectedRepositoryFile[]>([]);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isReadingDrop, setIsReadingDrop] = useState(false);
  const [error, setError] = useState('');

  const handleSelectedFiles = (selectedFiles: SelectedRepositoryFile[]) => {
    const repositoryFiles = selectedFiles.filter(({ path }) =>
      shouldIncludeFile(path),
    );

    if (repositoryFiles.length === 0) {
      setFiles([]);
      setError(
        'No supported source files were found. Sensitive files and unsupported file types are excluded.',
      );
      return;
    }

    if (repositoryFiles.length > MAX_FILES) {
      setFiles([]);
      setError(
        `This scan supports up to ${MAX_FILES} files. Select a smaller repository subset and try again.`,
      );
      return;
    }

    setError('');
    setFiles(repositoryFiles);
  };

  const handleFiles = (incomingFiles: FileList | File[]) => {
    const repositoryFiles = filterRepositoryFiles(incomingFiles);

    if (repositoryFiles.length === 0) {
      setFiles([]);
      setError(
        'No supported source files were found. Sensitive files and unsupported file types are excluded.',
      );
      return;
    }

    if (repositoryFiles.length > MAX_FILES) {
      setFiles([]);
      setError(
        `This scan supports up to ${MAX_FILES} files. Your selection contains ${repositoryFiles.length} supported files. Select a smaller subset and try again.`,
      );
      return;
    }

    setError('');
    setFiles(repositoryFiles);
  };

  const handleBrowseFolder = () => {
    if (!isAnalyzing && !isReadingDrop) {
      folderInputRef.current?.click();
    }
  };

  const handleBrowseFiles = () => {
    if (!isAnalyzing && !isReadingDrop) {
      filesInputRef.current?.click();
    }
  };

  const handleDragEnter = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();

    if (isAnalyzing || isReadingDrop) return;

    dragCounter.current += 1;
    setIsDragging(true);
  };

  const handleDragLeave = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();

    if (isAnalyzing || isReadingDrop) return;

    dragCounter.current -= 1;

    if (dragCounter.current <= 0) {
      dragCounter.current = 0;
      setIsDragging(false);
    }
  };

  const handleDragOver = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();

    if (!isAnalyzing && !isReadingDrop) {
      event.dataTransfer.dropEffect = 'copy';
    }
  };

  const handleDrop = async (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();

    dragCounter.current = 0;
    setIsDragging(false);

    if (isAnalyzing || isReadingDrop) return;

    setError('');

    const items = Array.from(event.dataTransfer.items);

    const entries = items
      .filter((item) => item.kind === 'file')
      .map((item) => {
        const getEntry = (item as DataTransferItemWithEntry).webkitGetAsEntry;
        return getEntry ? getEntry.call(item) : null;
      });

    const usableEntries: DirectoryEntryLike[] = entries.filter(
      (entry): entry is DirectoryEntryLike => {
        if (!entry || typeof entry !== 'object') return false;

        const candidate = entry as Partial<DirectoryEntryLike>;

        return (
          typeof candidate.name === 'string' &&
          (candidate.isFile === true || candidate.isDirectory === true)
        );
      },
    );

    if (usableEntries.length > 0) {
      setIsReadingDrop(true);

      try {
        const collected: SelectedRepositoryFile[] = [];
        const counter = { value: 0 };

        for (const entry of usableEntries) {
          await collectEntryFiles(entry, '', collected, counter);
        }

        handleSelectedFiles(collected);
      } catch (dropError) {
        setFiles([]);
        setError(
          dropError instanceof Error
            ? dropError.message
            : 'Unable to read the dropped repository.',
        );
      } finally {
        setIsReadingDrop(false);
      }

      return;
    }

    const droppedFiles = event.dataTransfer.files;

    if (droppedFiles.length === 0) {
      setError(
        'No readable files were found. Try Browse Repository or Select Individual Files.',
      );
      return;
    }

    handleFiles(droppedFiles);
  };

  const analyzeRepository = async () => {
    if (files.length === 0 || isAnalyzing || isReadingDrop) return;

    try {
      setIsAnalyzing(true);
      setError('');
      onAnalysisStart?.();
      onStatusChange?.('ANALYZING REPOSITORY');

      const repositoryFiles: RepositoryPayloadFile[] = [];

      for (const { file, path } of files) {
        const content = (await file.text()).slice(0, MAX_FILE_CHARACTERS);

        repositoryFiles.push({
          name: path,
          content,
        });
      }

      const requestBody = JSON.stringify({
        files: repositoryFiles,
      });

      const requestBytes = new TextEncoder().encode(requestBody).byteLength;

      if (requestBytes > MAX_REQUEST_BYTES) {
        throw new Error(
          'The selected files exceed the safe request-size limit. Select fewer or smaller files and try again.',
        );
      }

      const response = await fetch(`${API_BASE_URL}/api/analyze`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: requestBody,
      });

      const data = (await response.json()) as RepositoryAnalysis & {
        message?: string;
      };

      if (!response.ok || !data.success) {
        throw new Error(
          data.message || `Repository analysis failed (${response.status}).`,
        );
      }

      onStatusChange?.('SCAN COMPLETE');
      onAnalysisComplete(data);
    } catch (analysisError) {
      setError(
        analysisError instanceof Error
          ? analysisError.message
          : 'Unable to analyze repository.',
      );

      onStatusChange?.('ENGINE READY');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const busy = isAnalyzing || isReadingDrop;

  return (
    <div
      className={`repository-dropzone ${
        isDragging ? 'dragging' : ''
      } ${busy ? 'analyzing' : ''} ${files.length > 0 ? 'has-files' : ''}`}
      onDragEnter={handleDragEnter}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
      aria-busy={busy}
    >
      <input
        ref={folderInputRef}
        type="file"
        multiple
        hidden
        disabled={busy}
        {...({
          webkitdirectory: 'true',
          directory: 'true',
        } as InputHTMLAttributes<HTMLInputElement>)}
        onChange={(event) => {
          if (event.target.files) {
            handleFiles(event.target.files);
          }

          event.target.value = '';
        }}
      />

      <input
        ref={filesInputRef}
        type="file"
        multiple
        hidden
        disabled={busy}
        onChange={(event) => {
          if (event.target.files) {
            handleFiles(event.target.files);
          }

          event.target.value = '';
        }}
      />

      <div className="dropzone-icon" aria-hidden="true">
        <svg
          viewBox="0 0 24 24"
          width="28"
          height="28"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.8"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
          <polyline points="17 8 12 3 7 8" />
          <line x1="12" y1="3" x2="12" y2="15" />
        </svg>
      </div>

      <h3>
        {isAnalyzing
          ? 'Analyzing repository...'
          : isReadingDrop
            ? 'Reading dropped files...'
            : isDragging
              ? 'Release to add files'
              : files.length > 0
                ? `${files.length} source files ready`
                : 'Drop your repository here'}
      </h3>

      <p>
        {isAnalyzing
          ? 'DevPulse is analyzing your code and security posture.'
          : isReadingDrop
            ? 'Collecting supported files and excluding ignored paths.'
            : files.length > 0
              ? 'Selection ready. You can scan it or choose a different selection.'
              : 'Drop a project folder or multiple source files. Sensitive files and unsupported formats are excluded.'}
      </p>

      {!busy && files.length === 0 && (
        <div className="repository-actions">
          <button
            type="button"
            className="browse-button"
            onClick={handleBrowseFolder}
          >
            Browse Repository
          </button>

          <button
            type="button"
            className="change-repository-button"
            onClick={handleBrowseFiles}
          >
            Select Individual Files
          </button>
        </div>
      )}

      {files.length > 0 && !busy && (
        <div className="repository-actions">
          <div className="file-summary">{files.length} source files ready</div>

          <button
            type="button"
            className="scan-button repository-scan-button"
            onClick={analyzeRepository}
          >
            Analyze Repository
          </button>

          <button
            type="button"
            className="change-repository-button"
            onClick={handleBrowseFolder}
          >
            Choose another repository
          </button>

          <button
            type="button"
            className="change-repository-button"
            onClick={handleBrowseFiles}
          >
            Choose individual files
          </button>
        </div>
      )}

      {busy && (
        <div className="analysis-status" role="status" aria-live="polite">
          <span className="analysis-spinner" />
          {isReadingDrop
            ? 'Reading dropped files...'
            : 'Running security analysis...'}
        </div>
      )}

      {error && (
        <div className="analysis-error" role="alert">
          {error}
        </div>
      )}
    </div>
  );
}

export default RepositoryDropzone;
