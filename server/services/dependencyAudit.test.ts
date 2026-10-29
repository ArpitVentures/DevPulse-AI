import { afterEach, describe, expect, it, vi } from 'vitest';
import { auditNpmDependencies } from './dependencyAudit';

describe('Dependency Audit tests', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('rejects invalid JSON', async () => {
    const result = await auditNpmDependencies('{ invalid json');

    expect(result.success).toBe(false);
    expect(result.error).toContain('Invalid package-lock.json');
    expect(result.dependencies).toHaveLength(0);
  });

  it('handles an empty package lock', async () => {
    const result = await auditNpmDependencies(
      JSON.stringify({
        name: 'test-project',
        lockfileVersion: 3,
        packages: {},
      }),
    );

    expect(result.success).toBe(true);
    expect(result.dependenciesScanned).toBe(0);
    expect(result.vulnerabilitiesFound).toBe(0);
    expect(result.dependencies).toHaveLength(0);
  });

  it('rejects a non-object JSON structure', async () => {
    const result = await auditNpmDependencies('[]');

    expect(result.success).toBe(false);
    expect(result.error).toContain('Invalid package-lock.json structure');
  });

  it('reports a clean dependency when OSV returns no vulnerabilities', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ results: [{ vulns: [] }] }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      ),
    );

    const result = await auditNpmDependencies(
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { name: 'test-project', version: '1.0.0' },
          'node_modules/example-package': { version: '1.2.3' },
        },
      }),
    );

    expect(result.success).toBe(true);
    expect(result.dependenciesScanned).toBe(1);
    expect(result.vulnerabilitiesFound).toBe(0);
    expect(result.vulnerableDependencies).toBe(0);
  });

  it('reports an OSV API HTTP failure', async () => {
    vi.stubGlobal(
      'fetch',
      vi
        .fn()
        .mockResolvedValue(
          new Response('Service unavailable', { status: 503 }),
        ),
    );

    const result = await auditNpmDependencies(
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { name: 'test-project', version: '1.0.0' },
          'node_modules/example-package': { version: '1.2.3' },
        },
      }),
    );

    expect(result.success).toBe(false);
    expect(result.error).toContain('HTTP 503');
  });

  it('maps advisory severity and fixed versions correctly', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            results: [
              {
                vulns: [
                  {
                    id: 'GHSA-test-high',
                    summary: 'Test high severity vulnerability',
                    database_specific: { severity: 'HIGH' },
                    affected: [
                      {
                        package: {
                          name: 'example-package',
                          ecosystem: 'npm',
                        },
                        ranges: [
                          {
                            type: 'ECOSYSTEM',
                            events: [{ introduced: '0' }, { fixed: '1.2.4' }],
                          },
                        ],
                      },
                    ],
                    references: [],
                  },
                ],
              },
            ],
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          },
        ),
      ),
    );

    const result = await auditNpmDependencies(
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { name: 'test-project', version: '1.0.0' },
          'node_modules/example-package': { version: '1.2.3' },
        },
      }),
    );

    expect(result.success).toBe(true);
    expect(result.vulnerabilitiesFound).toBe(1);
    expect(result.dependencies[0].vulnerabilities[0].severity).toBe('HIGH');
    expect(result.dependencies[0].vulnerabilities[0].fixedVersions).toContain(
      '1.2.4',
    );
  });

  it('preserves unknown severity when no severity data is available', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            results: [
              {
                vulns: [
                  {
                    id: 'GHSA-test-unknown',
                    summary: 'Advisory without severity data',
                    affected: [
                      {
                        package: {
                          name: 'example-package',
                          ecosystem: 'npm',
                        },
                        ranges: [
                          {
                            type: 'ECOSYSTEM',
                            events: [{ introduced: '0' }, { fixed: '1.2.4' }],
                          },
                        ],
                      },
                    ],
                    references: [],
                  },
                ],
              },
            ],
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          },
        ),
      ),
    );

    const result = await auditNpmDependencies(
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { name: 'test-project', version: '1.0.0' },
          'node_modules/example-package': { version: '1.2.3' },
        },
      }),
    );

    expect(result.success).toBe(true);
    expect(result.dependencies[0].vulnerabilities[0].severity).toBe('UNKNOWN');
  });

  it('does not mix fixed versions from unrelated affected packages', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            results: [
              {
                vulns: [
                  {
                    id: 'GHSA-test-multiple',
                    summary: 'Advisory affecting multiple packages',
                    database_specific: { severity: 'MEDIUM' },
                    affected: [
                      {
                        package: {
                          name: 'example-package',
                          ecosystem: 'npm',
                        },
                        ranges: [
                          {
                            type: 'ECOSYSTEM',
                            events: [{ introduced: '0' }, { fixed: '1.2.4' }],
                          },
                        ],
                      },
                      {
                        package: {
                          name: 'another-package',
                          ecosystem: 'npm',
                        },
                        ranges: [
                          {
                            type: 'ECOSYSTEM',
                            events: [{ introduced: '0' }, { fixed: '9.9.9' }],
                          },
                        ],
                      },
                    ],
                    references: [],
                  },
                ],
              },
            ],
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          },
        ),
      ),
    );

    const result = await auditNpmDependencies(
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { name: 'test-project', version: '1.0.0' },
          'node_modules/example-package': { version: '1.2.3' },
        },
      }),
    );

    expect(result.success).toBe(true);

    const vulnerability = result.dependencies[0].vulnerabilities[0];

    expect(vulnerability.fixedVersions).toContain('1.2.4');
    expect(vulnerability.fixedVersions).not.toContain('9.9.9');
  });

});
