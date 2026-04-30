# Contributing to Trinket

Thanks for your interest in contributing to Trinket! This document outlines the process for contributing to the project.

## Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/trinketapp/trinket-oss/issues)
2. If not, create a new issue with:
   - A clear, descriptive title
   - Steps to reproduce the bug
   - Expected vs actual behavior
   - Browser/OS/Node version if relevant
   - Screenshots if applicable

## Suggesting Features

Open an issue with the `enhancement` label describing:
- The problem you're trying to solve
- Your proposed solution
- Any alternatives you've considered

## Pull Requests

### Before You Start

- For small fixes (typos, minor bugs), feel free to submit a PR directly
- For larger changes, open an issue first to discuss the approach
- Security-related PRs follow a separate review process — see the [Security](#security) section below and [SECURITY.md](SECURITY.md) before opening one

### Development Setup

1. Fork and clone the repository
2. Copy config and add your settings:
   ```bash
   cp config/local.example.yaml config/local.yaml
   ```
3. Start the development environment:
   ```bash
   docker-compose up
   ```

### Making Changes

1. Create a branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes following the code style below

3. Test your changes:
   ```bash
   npm test
   ```

4. Commit with a clear message:
   ```bash
   git commit -m "Add feature X that does Y"
   ```

### Code Style

- Use 2 spaces for indentation
- Use single quotes for strings
- Add semicolons at the end of statements
- Keep lines under 120 characters
- Use descriptive variable names

### Submitting

1. Push to your fork
2. Open a Pull Request
3. Wait for review

## Security

Trinket executes untrusted learner code on behalf of authenticated users (often minors) and hosts educator-authored courseware, so security findings are taken seriously. The full policy, threat model, supported versions, and response-time commitments are documented in [SECURITY.md](SECURITY.md).

### Reporting Security Vulnerabilities

**Please do NOT report security vulnerabilities through public GitHub issues, pull requests, or discussion threads.** Follow the private disclosure process described in [SECURITY.md](SECURITY.md). For self-hosted deployments, operators may substitute their own maintainer-controlled contact channel as documented there.

### Security Pull Request Guidelines

Pull requests that remediate security vulnerabilities follow a separate, expedited review process. To help maintainers triage and merge security fixes quickly, please:

- **Annotate every changed line** that introduces or modifies security behavior with an inline comment of the form `// SECURITY: [threat addressed]` (for example, `// SECURITY: SHA-256 replaces MD5 to mitigate cryptographic weakness`). Annotations enable retroactive audit and downstream SIEM ingestion.
- **Use atomic commits** with the message format `security: [severity] fix [description] in [file]` (for example, `security: [high] fix EOL Node 16 base image upgrade to Node 20 LTS in Dockerfile`). One CVE or vulnerability class per commit so individual fixes can be reverted in isolation.
- **Reference the CVE or advisory link** in the commit message body (npm Advisory Database, GitHub Security Advisory, Snyk Vulnerability DB, NVD, etc.) so reviewers can cross-check severity and patch availability.
- **Pass automated security scans** before opening the PR — at minimum, `npm audit --audit-level=high` against the root `package.json` and each `serverside/*/manager/package.json`, plus the ESLint security plugin (`npx eslint lib/ config/ serverside/*/manager/ --no-fix`). The CI pipeline gates on these scans.
- **Include or update tests in `test/security/`** when applicable — for example, regression tests for authentication bypass, IDOR, NoSQL operator injection, session fixation, or upload validation. Follow the existing Mocha + Supertest pattern used elsewhere in `test/`.
- **Keep changes minimal**. Modify only the files and functions directly implicated by the vulnerability; do not refactor unrelated code; do not upgrade dependencies that are not directly implicated in a discovered finding.

If your PR closes a previously reported issue, link the report (or its tracking advisory) in the description so the disclosure timeline can be coordinated. See [SECURITY.md](SECURITY.md) for our remediation prioritization targets and the security controls already in place.

## Code of Conduct

Be respectful and constructive. We're all here to make coding education better.

## Questions?

Open an issue with the `question` label or reach out to the maintainers.
