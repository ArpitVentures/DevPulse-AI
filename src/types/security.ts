export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'REVIEW';

export type DependencySeverity =
  'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

export interface DependencyVulnerability {
  id: string;
  summary: string;
  severity: DependencySeverity;
  affectedVersions: string[];
  fixedVersions: string[];
  references: string[];
}

export interface AuditedDependency {
  name: string;
  version: string;
  vulnerabilities: DependencyVulnerability[];
}

export interface DependencyAuditResult {
  success: boolean;
  vulnerabilitiesFound: number;
  vulnerableDependencies: number;
  dependencies: AuditedDependency[];
  error?: string;
}

export interface FileAnalysis {
  filename: string;
  analysis: string;
  severity: Severity;
  aiExplanation?: string;
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
  dependencyAudit?: DependencyAuditResult;
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
