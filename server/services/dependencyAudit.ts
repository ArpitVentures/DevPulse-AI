const OSV_QUERY_BATCH_URL = 'https://api.osv.dev/v1/querybatch';
const OSV_VULN_DETAIL_URL = 'https://api.osv.dev/v1/vulns/';
const REQUEST_TIMEOUT_MS = 10_000;
const MAX_PACKAGES = 1000;

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
  ecosystem: 'npm';
  dependenciesScanned: number;
  vulnerableDependencies: number;
  vulnerabilitiesFound: number;
  dependencies: AuditedDependency[];
  error?: string;
}

interface PackageLock {
  lockfileVersion?: number;
  packages?: Record<
    string,
    {
      name?: string;
      version?: string;
      dev?: boolean;
      link?: boolean;
    }
  >;
  dependencies?: Record<
    string,
    {
      version?: string;
      dependencies?: Record<string, unknown>;
    }
  >;
}

interface OsvVulnerability {
  id?: string;
  summary?: string;
  details?: string;
  severity?: Array<{
    type?: string;
    score?: string;
  }>;
  affected?: Array<{
    package?: {
      name?: string;
      ecosystem?: string;
    };
    ranges?: Array<{
      type?: string;
      events?: Array<{
        introduced?: string;
        fixed?: string;
        last_affected?: string;
      }>;
    }>;
    versions?: string[];
  }>;
  references?: Array<{
    url?: string;
  }>;
  database_specific?: {
    severity?: string;
    cvss?: {
      score?: number;
      vectorString?: string;
    };
  };
}

interface OsvBatchResponse {
  results?: Array<{
    vulns?: OsvVulnerability[];
  }>;
}

interface PackageEntry {
  name: string;
  version: string;
}

function isValidPackageName(name: string): boolean {
  return (
    name.length > 0 &&
    name.length <= 214 &&
    !name.startsWith('-') &&
    !name.includes('\\') &&
    !name.includes(' ') &&
    !name.startsWith('/') &&
    !name.includes('..')
  );
}

function isValidVersion(version: string): boolean {
  return (
    version.length > 0 &&
    version.length <= 128 &&
    !version.startsWith('-') &&
    !/[\s/\\]/.test(version)
  );
}

function getPackageEntries(lock: PackageLock): PackageEntry[] {
  const entries: PackageEntry[] = [];

  if (lock.packages && typeof lock.packages === 'object') {
    for (const [path, pkg] of Object.entries(lock.packages)) {
      if (!path.startsWith('node_modules/')) {
        continue;
      }

      if (!pkg || typeof pkg.version !== 'string') {
        continue;
      }

      if (pkg.link === true) {
        continue;
      }

      const marker = '/node_modules/';
      const lastIndex = path.lastIndexOf(marker);

      const name =
        lastIndex >= 0
          ? path.slice(lastIndex + marker.length)
          : path.slice('node_modules/'.length);

      if (name && isValidPackageName(name) && isValidVersion(pkg.version)) {
        entries.push({ name, version: pkg.version });
      }
    }

    return entries;
  }

  function visit(dependencies: PackageLock['dependencies']): void {
    if (!dependencies) return;

    for (const [name, dependency] of Object.entries(dependencies)) {
      if (
        dependency &&
        typeof dependency.version === 'string' &&
        isValidPackageName(name) &&
        isValidVersion(dependency.version)
      ) {
        entries.push({
          name,
          version: dependency.version,
        });
      }

      visit(dependency?.dependencies as PackageLock['dependencies']);
    }
  }

  visit(lock.dependencies);

  return entries;
}

function getSeverity(vulnerability: OsvVulnerability): DependencySeverity {
  const dbSeverity = vulnerability.database_specific?.severity?.toUpperCase();
  if (dbSeverity) {
    if (dbSeverity.includes('CRITICAL')) return 'CRITICAL';
    if (dbSeverity.includes('HIGH')) return 'HIGH';
    if (dbSeverity.includes('MODERATE') || dbSeverity.includes('MEDIUM'))
      return 'MEDIUM';
    if (dbSeverity.includes('LOW')) return 'LOW';
  }

  const scores = vulnerability.severity ?? [];
  for (const entry of scores) {
    const score = entry.score;
    if (!score) continue;

    const numeric = Number(score);
    if (Number.isFinite(numeric) && numeric >= 0 && numeric <= 10) {
      if (numeric >= 9) return 'CRITICAL';
      if (numeric >= 7) return 'HIGH';
      if (numeric >= 4) return 'MEDIUM';
      if (numeric > 0) return 'LOW';
    }
  }

  const cvssScore = vulnerability.database_specific?.cvss?.score;
  if (typeof cvssScore === 'number') {
    if (cvssScore >= 9) return 'CRITICAL';
    if (cvssScore >= 7) return 'HIGH';
    if (cvssScore >= 4) return 'MEDIUM';
    if (cvssScore > 0) return 'LOW';
  }

  return 'UNKNOWN';
}

function extractFixedVersions(
  vulnerability: OsvVulnerability,
  packageName: string,
): string[] {
  const fixedVersions = new Set<string>();

  for (const affected of vulnerability.affected ?? []) {
    if (
      affected.package?.name !== packageName ||
      affected.package?.ecosystem !== 'npm'
    ) {
      continue;
    }

    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed) {
          fixedVersions.add(event.fixed);
        }
      }
    }
  }

  return [...fixedVersions];
}

async function fetchFullAdvisoryIfNeeded(
  vulnerability: OsvVulnerability,
  packageName: string,
  signal: AbortSignal,
): Promise<OsvVulnerability> {
  const existingFixed = extractFixedVersions(vulnerability, packageName);
  const existingSeverity = getSeverity(vulnerability);

  if (existingFixed.length > 0 && existingSeverity !== 'UNKNOWN') {
    return vulnerability;
  }

  if (!vulnerability.id) {
    return vulnerability;
  }

  try {
    const response = await fetch(
      `${OSV_VULN_DETAIL_URL}${encodeURIComponent(vulnerability.id)}`,
      {
        headers: { Accept: 'application/json' },
        signal,
      },
    );

    if (response.ok) {
      const fullDetails = (await response.json()) as OsvVulnerability;
      return {
        ...vulnerability,
        ...fullDetails,
        database_specific: {
          ...vulnerability.database_specific,
          ...fullDetails.database_specific,
        },
      };
    }
  } catch {

  }

  return vulnerability;
}

function mapVulnerability(
  vulnerability: OsvVulnerability,
  packageName: string,
): DependencyVulnerability {
  const affectedVersions = new Set<string>();
  const fixedVersions = extractFixedVersions(vulnerability, packageName);

  for (const affected of vulnerability.affected ?? []) {
    if (
      affected.package?.name === packageName &&
      affected.package?.ecosystem === 'npm'
    ) {
      for (const version of affected.versions ?? []) {
        affectedVersions.add(version);
      }
    }
  }

  return {
    id: vulnerability.id ?? 'UNKNOWN-ID',
    summary:
      vulnerability.summary ??
      vulnerability.details?.slice(0, 300) ??
      'Known vulnerability advisory; review the linked source.',
    severity: getSeverity(vulnerability),
    affectedVersions: [...affectedVersions],
    fixedVersions,
    references: (vulnerability.references ?? [])
      .map((reference) => reference.url)
      .filter((url): url is string => Boolean(url))
      .slice(0, 10),
  };
}

export async function auditNpmDependencies(
  content: string,
): Promise<DependencyAuditResult> {
  let lock: PackageLock;

  try {
    lock = JSON.parse(content) as PackageLock;
  } catch {
    return {
      success: false,
      ecosystem: 'npm',
      dependenciesScanned: 0,
      vulnerableDependencies: 0,
      vulnerabilitiesFound: 0,
      dependencies: [],
      error: 'Invalid package-lock.json: unable to parse JSON.',
    };
  }

  if (!lock || typeof lock !== 'object' || Array.isArray(lock)) {
    return {
      success: false,
      ecosystem: 'npm',
      dependenciesScanned: 0,
      vulnerableDependencies: 0,
      vulnerabilitiesFound: 0,
      dependencies: [],
      error: 'Invalid package-lock.json structure.',
    };
  }

  const packages = getPackageEntries(lock);

  if (packages.length === 0) {
    return {
      success: true,
      ecosystem: 'npm',
      dependenciesScanned: 0,
      vulnerableDependencies: 0,
      vulnerabilitiesFound: 0,
      dependencies: [],
    };
  }

  if (packages.length > MAX_PACKAGES) {
    return {
      success: false,
      ecosystem: 'npm',
      dependenciesScanned: 0,
      vulnerableDependencies: 0,
      vulnerabilitiesFound: 0,
      dependencies: [],
      error: `Dependency limit exceeded. Maximum supported: ${MAX_PACKAGES}.`,
    };
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(OSV_QUERY_BATCH_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({
        queries: packages.map((pkg) => ({
          package: {
            name: pkg.name,
            ecosystem: 'npm',
          },
          version: pkg.version,
        })),
      }),
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new Error(`OSV API returned HTTP ${response.status}.`);
    }

    const data = (await response.json()) as OsvBatchResponse;

    if (
      !Array.isArray(data.results) ||
      data.results.length !== packages.length
    ) {
      throw new Error('OSV API returned an unexpected response.');
    }

    const dependencies: AuditedDependency[] = await Promise.all(
      packages.map(async (pkg, index) => {
        const rawVulns = data.results?.[index]?.vulns ?? [];

        const enrichedVulns = await Promise.all(
          rawVulns.map((v) =>
            fetchFullAdvisoryIfNeeded(v, pkg.name, controller.signal),
          ),
        );

        const vulnerabilities = enrichedVulns.map((v) =>
          mapVulnerability(v, pkg.name),
        );

        return {
          ...pkg,
          vulnerabilities,
        };
      }),
    );

    const vulnerableDependencies = dependencies.filter(
      (dependency) => dependency.vulnerabilities.length > 0,
    ).length;

    const vulnerabilitiesFound = dependencies.reduce(
      (total, dependency) => total + dependency.vulnerabilities.length,
      0,
    );

    return {
      success: true,
      ecosystem: 'npm',
      dependenciesScanned: packages.length,
      vulnerableDependencies,
      vulnerabilitiesFound,
      dependencies,
    };
  } catch (error) {
    return {
      success: false,
      ecosystem: 'npm',
      dependenciesScanned: 0,
      vulnerableDependencies: 0,
      vulnerabilitiesFound: 0,
      dependencies: [],
      error:
        error instanceof Error ? error.message : 'Dependency audit failed.',
    };
  } finally {
    clearTimeout(timeout);
  }
}
