import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import RepositoryDropzone, {
  type EngineStatus,
} from './components/RepositoryDropzone';
import SecurityEnvironment from './components/SecurityEnvironment';
import ReactMarkdown from 'react-markdown';
import type { RepositoryAnalysis, DependencySeverity } from './types/security';
import Logo from './components/Logo';

const rank: Record<DependencySeverity, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  UNKNOWN: 0,
};

function App() {
  const [engineStatus, setEngineStatus] =
    useState<EngineStatus>('ENGINE READY');

  const [analysisResult, setAnalysisResult] =
    useState<RepositoryAnalysis | null>(null);

  const [expandedFiles, setExpandedFiles] = useState<Set<string>>(new Set());

  const handleAnalysisComplete = (result: RepositoryAnalysis) => {
    setAnalysisResult(result);
    setEngineStatus('SCAN COMPLETE');

    setExpandedFiles(new Set());

    setTimeout(() => {
      document
        .getElementById('security-results')
        ?.scrollIntoView({ behavior: 'smooth' });
    }, 100);
  };

  const toggleReport = (filename: string) => {
    setExpandedFiles((current) => {
      const next = new Set(current);

      if (next.has(filename)) {
        next.delete(filename);
      } else {
        next.add(filename);
      }

      return next;
    });
  };

  const isScanning =
    engineStatus !== 'ENGINE READY' && engineStatus !== 'SCAN COMPLETE';

  const severityCounts = analysisResult
    ? analysisResult.results.reduce(
        (counts, result) => {
          if (result.severity === 'REVIEW' && result.findings.length === 0) {
            counts.review += 1;
            return counts;
          }

          if (result.dependencyAudit?.success) {
            const vulnerabilities = result.dependencyAudit.dependencies.flatMap(
              (dependency) => dependency.vulnerabilities,
            );

            if (vulnerabilities.length > 0) {
              const highestSeverity =
                vulnerabilities.reduce<DependencySeverity>(
                  (highest, vulnerability) => {
                    return rank[vulnerability.severity] > rank[highest]
                      ? vulnerability.severity
                      : highest;
                  },
                  'UNKNOWN',
                );

              switch (highestSeverity) {
                case 'CRITICAL':
                  counts.critical += 1;
                  break;
                case 'HIGH':
                  counts.high += 1;
                  break;
                case 'MEDIUM':
                  counts.medium += 1;
                  break;
                case 'LOW':
                  counts.low += 1;
                  break;
                default:
                  counts.review += 1;
              }

              return counts;
            }
          }

          if (result.findings.length === 0 && result.severity !== 'REVIEW') {
            counts.low += 1;
            return counts;
          }

          for (const finding of result.findings) {
            switch (finding.severity) {
              case 'CRITICAL':
                counts.critical += 1;
                break;
              case 'HIGH':
                counts.high += 1;
                break;
              case 'MEDIUM':
                counts.medium += 1;
                break;
              case 'LOW':
                counts.low += 1;
                break;
            }
          }

          return counts;
        },
        {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          review: 0,
        },
      )
    : {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        review: 0,
      };

  return (
    <div className="app">
      <header className="app-header">
        <div>
          <h1>
            <Logo size={40} variant="full" />
          </h1>
          <p>Autonomous Code Security</p>
        </div>

        <div className={`system-status ${isScanning ? 'active' : ''}`}>
          <span className="status-dot"></span>
          <span>{engineStatus}</span>
        </div>
      </header>

      <main className="main-content">
        <div className="hero-layout">
          <motion.section
            className="hero"
            initial={{ opacity: 0, y: 24 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, ease: 'easeOut' }}
          >
            <span className="eyebrow">AI-POWERED CODE SECURITY</span>

            <h2>
              Find vulnerabilities
              <br />
              before they become incidents.
            </h2>

            <p>
              Upload your repository and let DevPulse analyze your code,
              research live security intelligence, and generate actionable
              remediation.
            </p>

            <div id="repository-scanner">
              <RepositoryDropzone
                onStatusChange={(status) => setEngineStatus(status)}
                onAnalysisComplete={handleAnalysisComplete}
              />
            </div>
          </motion.section>

          <aside className="hero-engine">
            <SecurityEnvironment active={isScanning} status={engineStatus} />
          </aside>
        </div>

        {analysisResult && (
          <motion.section
            id="security-results"
            className="security-results"
            initial={{ opacity: 0, y: 25 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, ease: 'easeOut' }}
          >
            <div className="results-header">
              <div>
                <span className="eyebrow">SECURITY SCAN COMPLETE</span>

                <h2>Security Intelligence</h2>

                <p>
                  DevPulse analyzed{' '}
                  <strong>{analysisResult.filesAnalyzed}</strong>{' '}
                  {analysisResult.filesAnalyzed === 1 ? 'file' : 'files'} and
                  generated actionable security findings.
                </p>
              </div>

              <div className="scan-status">
                <span className="status-dot" />
                Scan Complete
              </div>
            </div>

            <div className="severity-summary">
              <motion.div
                className="severity-summary-card critical"
                whileHover={{ y: -4 }}
                transition={{ type: 'spring', stiffness: 300 }}
              >
                <strong>{severityCounts.critical}</strong>
                <span>CRITICAL</span>
              </motion.div>

              <motion.div
                className="severity-summary-card high"
                whileHover={{ y: -4 }}
                transition={{ type: 'spring', stiffness: 300 }}
              >
                <strong>{severityCounts.high}</strong>
                <span>HIGH</span>
              </motion.div>

              <motion.div
                className="severity-summary-card medium"
                whileHover={{ y: -4 }}
                transition={{ type: 'spring', stiffness: 300 }}
              >
                <strong>{severityCounts.medium}</strong>
                <span>MEDIUM</span>
              </motion.div>

              <motion.div
                className="severity-summary-card low"
                whileHover={{ y: -4 }}
                transition={{ type: 'spring', stiffness: 300 }}
              >
                <strong>{severityCounts.low}</strong>
                <span>CLEAN / LOW</span>
              </motion.div>

              <motion.div
                className="severity-summary-card review"
                whileHover={{ y: -4 }}
                transition={{ type: 'spring', stiffness: 300 }}
              >
                <strong>{severityCounts.review}</strong>
                <span>REVIEW</span>
              </motion.div>
            </div>

            <div className="results-grid">
              {analysisResult.results.map((result, index) => {
                const isExpanded = expandedFiles.has(result.filename);

                return (
                  <motion.article
                    className={`security-result-card ${
                      isExpanded ? 'expanded' : ''
                    }`}
                    key={result.filename}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{
                      duration: 0.4,
                      delay: index * 0.08,
                      ease: 'easeOut',
                    }}
                  >
                    <div className="result-card-top">
                      <div>
                        <span className="result-label">ANALYZED FILE</span>
                        <h3>{result.filename}</h3>
                      </div>

                      <span
                        className={`severity severity-${result.severity.toLowerCase()}`}
                      >
                        {result.severity}
                      </span>
                    </div>

                    <button
                      type="button"
                      className="report-toggle"
                      onClick={() => toggleReport(result.filename)}
                      aria-expanded={isExpanded}
                    >
                      <span>
                        {isExpanded
                          ? 'Hide Security Report'
                          : 'View Security Report'}
                      </span>

                      <span
                        className={`report-toggle-icon ${
                          isExpanded ? 'open' : ''
                        }`}
                      >
                        ↓
                      </span>
                    </button>

                    <AnimatePresence>
                      {isExpanded && (
                        <motion.div
                          className="report-content"
                          initial={{ opacity: 0, height: 0 }}
                          animate={{ opacity: 1, height: 'auto' }}
                          exit={{ opacity: 0, height: 0 }}
                          transition={{ duration: 0.35, ease: 'easeInOut' }}
                        >
                          <div className="report-section">
                            <span className="result-label">
                              SECURITY REPORT
                            </span>

                            <div className="security-report">
                              <ReactMarkdown>
                                {result.analysis
                                  .replace(/\\#/g, '#')
                                  .replace(/\\\*/g, '*')
                                  .replace(/\\`/g, '`')}
                              </ReactMarkdown>
                            </div>
                          </div>

                          {result.aiExplanation && (
                            <div className="research-section">
                              <div className="research-heading">
                                <span className="result-label">
                                  AI SECURITY EXPLANATION
                                </span>
                                <span className="tavily-badge">
                                  NEBIUS · NEMOTRON
                                </span>
                              </div>

                              <div className="research-answer">
                                <ReactMarkdown>
                                  {result.aiExplanation}
                                </ReactMarkdown>
                              </div>
                            </div>
                          )}

                          {result.research && (
                            <div className="research-section">
                              <div className="research-heading">
                                <span className="result-label">
                                  LIVE SECURITY INTELLIGENCE
                                </span>

                                <span className="tavily-badge">TAVILY</span>

                                <p className="research-disclaimer">
                                  External security research and remediation
                                  guidance. Severity ratings shown in the
                                  Security Report are determined by DevPulse's
                                  static analysis engine; external sources
                                  provide additional context and do not override
                                  those ratings.
                                </p>
                              </div>

                              {result.research.answer && (
                                <p className="research-answer">
                                  {result.research.answer}
                                </p>
                              )}

                              {result.research.sources.length > 0 && (
                                <div className="research-sources">
                                  <span className="result-label">SOURCES</span>

                                  {result.research.sources.map((source) => (
                                    <a
                                      key={source.url}
                                      href={source.url}
                                      target="_blank"
                                      rel="noreferrer"
                                      className="research-source"
                                    >
                                      <span>{source.title}</span>
                                      <span>↗</span>
                                    </a>
                                  ))}
                                </div>
                              )}
                            </div>
                          )}
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </motion.article>
                );
              })}
            </div>
          </motion.section>
        )}
      </main>
    </div>
  );
}

export default App;
