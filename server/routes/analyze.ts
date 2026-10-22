import { Router, type Request, type Response } from 'express';
import { analyzeRepository, type RepositoryFile } from '../services/analyzer';

const router = Router();

const MAX_FILES = 20;
const MAX_FILE_CHARACTERS = 30_000;

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

    const invalidFile = files.some((file) => {
      if (!file || typeof file !== 'object') {
        return true;
      }

      if (!('name' in file) || !('content' in file)) {
        return true;
      }

      return (
        typeof file.name !== 'string' ||
        file.name.trim().length === 0 ||
        typeof file.content !== 'string' ||
        file.content.length > MAX_FILE_CHARACTERS
      );
    });

    if (invalidFile) {
      return res.status(400).json({
        success: false,
        message:
          'Invalid repository file. Each file needs a name and string content no longer than 30,000 characters.',
      });
    }

    const repositoryFiles = files as RepositoryFile[];
    const result = await analyzeRepository(repositoryFiles);

    return res.status(200).json(result);
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
