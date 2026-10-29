import { describe, expect, it } from 'vitest';
import { runDetectors } from './detectors';

describe('DevPulse AI — Detector baseline tests', () => {
  it('detects hardcoded secrets', () => {
    const code = `
      const apiKey = "sk_test_example123456789";
    `;

    const findings = runDetectors('config.ts', code);

    expect(findings.length).toBeGreaterThan(0);
  });

  it('detects dangerous dynamic code execution', () => {
    const code = `
      const result = eval(userInput);
    `;

    const findings = runDetectors('app.js', code);

    expect(findings.length).toBeGreaterThan(0);
  });

  it('does not flag harmless console logging', () => {
    const code = `
      console.log("Application started successfully");
    `;

    const findings = runDetectors('app.js', code);

    expect(findings).toHaveLength(0);
  });

  it('detects whether logging a user object is detected', () => {
    const code = `
    console.log("User Found:", user);
  `;

    const findings = runDetectors('adminMiddleware.js', code);

    expect(
      findings.some((finding) => finding.category === 'log_sensitive'),
    ).toBe(true);
  });

  it('does not flag logging a harmless status message', () => {
    const code = `
    console.log("Server started successfully");
  `;

    const findings = runDetectors('server.js', code);

    expect(findings).toHaveLength(0);
  });


  it('does not flag harmless user-count logging', () => {
    const code = `
      console.log("Current user count:", count);
    `;

    const findings = runDetectors('server.js', code);

    expect(findings).toHaveLength(0);
  });

  it('detects password logging', () => {
    const code = `
      console.log("password:", password);
    `;

    const findings = runDetectors('auth.js', code);

    expect(
      findings.some((finding) => finding.category === 'log_sensitive'),
    ).toBe(true);
  });


  it('detects potential SQL query concatenation', () => {
    const code = `
    const query = "SELECT * FROM users WHERE id = " + userId;
    db.query(query);
  `;

    const findings = runDetectors('database.js', code);

    expect(findings.some((finding) => finding.category === 'sql_concat')).toBe(
      true,
    );
  });


  it('detects potential unsafe HTML injection', () => {
    const code = `
    element.innerHTML = userInput;
  `;

    const findings = runDetectors('app.js', code);

    expect(findings.some((finding) => finding.category === 'unsafe_dom')).toBe(
      true,
    );
  });

  it('detects permissive CORS configuration', () => {
    const code = `
    app.use(cors());
  `;

    const findings = runDetectors('server.js', code);

    expect(
      findings.some((finding) => finding.category === 'cors_wildcard'),
    ).toBe(true);
  });

  it('does not flag password-related error labels', () => {
    const code = `
    console.error("Forgot Password Error:", error.message);
  `;

    const findings = runDetectors('authControllers.js', code);

    expect(
      findings.some((finding) => finding.category === 'log_sensitive'),
    ).toBe(false);
  });

  it('detects explicit reset-token logging', () => {
    const code = `
    console.error("Password reset token:", resetToken);
  `;

    const findings = runDetectors('auth.js', code);

    expect(
      findings.some((finding) => finding.category === 'log_sensitive'),
    ).toBe(true);
  });


  it('does not flag RegExp.exec as dynamic code execution', () => {
    const code = `
      const commentMatch = /(?:^|\\s)\\/\\/(.*)$/.exec(line);
      return commentMatch?.[1]?.trim() ?? null;
    `;

    const findings = runDetectors('app.ts', code);

    expect(
      findings.some((finding) => finding.category === 'code_execution'),
    ).toBe(false);
  });

  it('does not flag a regex definition as unsafe HTML injection', () => {
    const code = String.raw`
      const pattern = /\.innerHTML\s*=|dangerouslySetInnerHTML/gi;
    `;

    const findings = runDetectors('app.ts', code);

    expect(findings.some((finding) => finding.category === 'unsafe_dom')).toBe(
      false,
    );
  });

  it('still detects actual eval calls', () => {
    const code = 'const result = eval(userInput);';

    const findings = runDetectors('app.js', code);

    expect(
      findings.some((finding) => finding.category === 'code_execution'),
    ).toBe(true);
  });

  it('still detects actual unsafe HTML assignments', () => {
    const code = 'element.innerHTML = userInput;';

    const findings = runDetectors('app.js', code);

    expect(findings.some((finding) => finding.category === 'unsafe_dom')).toBe(
      true,
    );
  });

});
