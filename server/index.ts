import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { explainFindings } from './services/nebius';
import { researchSecurityIssue } from './services/tavily';
import analyzeRouter from './routes/analyze';

const app = express();
const PORT = Number(process.env.PORT) || 5000;

const allowedOrigins = (
  process.env.CLIENT_ORIGIN || 'http://localhost:5173,http://127.0.0.1:5173'
)
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: allowedOrigins,
  }),
);

app.use(express.json({ limit: '15mb' }));

app.get('/api/health', (_req, res) => {
  res.json({
    success: true,
    message: 'DevPulse AI backend is running',
  });
});

app.use('/api/analyze', analyzeRouter);

if (process.env.NODE_ENV !== 'production') {
  app.get('/api/test-nebius', async (_req, res) => {
    try {
      const result = await explainFindings(
        'test.js',
        'const message = "Hello, world!";',
        '- Connectivity test only. No confirmed security finding.',
      );

      return res.json({
        success: true,
        message: 'Nebius Nemotron connection is working.',
        result,
      });
    } catch (error) {
      console.error(
        '[DevPulse] Nebius test failed:',
        error instanceof Error ? error.message : 'Unknown error',
      );

      return res.status(500).json({
        success: false,
        message: 'Nebius connectivity test failed.',
      });
    }
  });

  app.get('/api/test-tavily', async (_req, res) => {
    try {
      const result = await researchSecurityIssue(
        'hardcoded passwords security vulnerability remediation',
      );

      return res.json({
        success: true,
        message: 'Tavily security research is working.',
        result,
      });
    } catch (error) {
      console.error(
        '[DevPulse] Tavily test failed:',
        error instanceof Error ? error.message : 'Unknown error',
      );

      return res.status(500).json({
        success: false,
        message: 'Tavily connectivity test failed.',
      });
    }
  });
}

app.listen(PORT, () => {
  console.log(`DevPulse AI API running on port ${PORT}`);
});
