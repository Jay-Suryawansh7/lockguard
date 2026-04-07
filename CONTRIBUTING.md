# Contributing to LockGuard

Thank you for your interest in contributing to LockGuard!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/<your-username>/lockguard.git`
3. Install dependencies: `npm install`
4. Run tests: `npm test`
5. Build: `npm run build`

## Development Workflow

1. Create a branch: `git checkout -b feat/my-feature`
2. Make your changes
3. Add tests for new functionality
4. Ensure tests pass: `npm test`
5. Build: `npm run build`
6. Commit with a clear message: `git commit -m "feat: add X"`
7. Push: `git push origin feat/my-feature`
8. Open a Pull Request

## Code Style

- TypeScript strict mode
- Run `npm run lint` before committing
- Follow existing patterns in the codebase

## Testing

Every new feature should have tests. Run:

```bash
npm test
npm run test:coverage
```

## Reporting Issues

- Search existing issues before opening a new one
- Include your Node.js version, npm version, and OS
- Include the output of `lockguard --verbose` if applicable
- For security issues, see [SECURITY.md](SECURITY.md)

## Pull Requests

- Reference the issue being addressed
- Keep PRs focused — one feature or fix per PR
- Include tests
- Update documentation if needed
