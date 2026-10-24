export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'REVIEW';

export interface FileAnalysis {
  filename: string;
  analysis: string;
  severity: Severity;
  findings: Array<{
    ruleId: string;
    category: string;
    severity: Exclude<Severity, 'REVIEW'>;
    title: string;
    impact: string;
    remediation: string;
    lines: number[];
    snippet: string;
  }>;
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
