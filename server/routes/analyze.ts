import { Router, type Request, type Response } from 'express';
import { analyzeRepository, type RepositoryFile } from '../services/analyzer';

const router = Router();

const MAX_FILES = 500;
const MAX_FILE_CHARACTERS = 200_000;
const MAX_PACKAGE_LOCK_CHARACTERS = 5_000_000;
const MAX_TOTAL_CHARACTERS = 12_000_000;

router.post('/', async (req: Request, res: Response) => {
  try {
    const body: unknown = req.body;

    if (
      !body ||
      typeof body !== 'object' ||
      !('files' in body) ||
      !Array.isArray(body.files)
    ) {
      return res.status(400).json({
        success: false,
        message: 'No valid repository files were provided.',
      });
    }

    const files: unknown[] = body.files;

    if (files.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Repository contains no files to analyze.',
      });
    }

    if (files.length > MAX_FILES) {
      return res.status(400).json({
        success: false,
        message: `A maximum of ${MAX_FILES} files can be analyzed per request.`,
      });
    }

    let totalCharacters = 0;

    const invalidFile = files.some((file) => {
      if (!file || typeof file !== 'object') {
        return true;
      }

      if (!('name' in file) || !('content' in file)) {
        return true;
      }

      if (
        typeof file.name !== 'string' ||
        file.name.trim().length === 0 ||
        typeof file.content !== 'string'
      ) {
        return true;
      }

      const normalizedName = file.name.replace(/\\/g, '/');

      const pathSegments = normalizedName.split('/');
      if (
        normalizedName.startsWith('/') ||
        /^[a-z]:/i.test(normalizedName) ||
        pathSegments.some((segment) => segment === '..' || segment === '.') ||
        normalizedName.includes('\0')
      ) {
        return true;
      }

      const isPackageLock = /(^|\/)package-lock\.json$/i.test(normalizedName);

      const maxCharacters = isPackageLock
        ? MAX_PACKAGE_LOCK_CHARACTERS
        : MAX_FILE_CHARACTERS;

      if (file.content.length > maxCharacters) {
        return true;
      }

      totalCharacters += file.content.length;

      return totalCharacters > MAX_TOTAL_CHARACTERS;
    });

    if (invalidFile) {
      return res.status(400).json({
        success: false,
        message:
          'Invalid repository payload. Check file paths, per-file limits (200,000 characters; package-lock.json 5,000,000), and the 12,000,000-character total limit.',
      });
    }

    const repositoryFiles = files as RepositoryFile[];
    const result = await analyzeRepository(repositoryFiles);

    return res.status(result.success ? 200 : 400).json(result);
  } catch (error) {
    console.error(
      '[DevPulse] Repository analysis request failed:',
      error instanceof Error ? error.message : 'Unknown error',
    );

    return res.status(500).json({
      success: false,
      message:
        'Repository analysis failed due to a server error. Please try again.',
    });
  }
});

export default router;
