export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'REVIEW';

export interface FileAnalysis {
  filename: string;
  analysis: string;
  severity: Severity;
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
