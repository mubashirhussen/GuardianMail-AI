# Contributing to GuardianMail AI

Thank you for your interest in contributing to the **GuardianMail AI** platform! Follow this guide to ensure smooth cooperation, formatting compliance, and high quality code reviews.

---

## 1. Code Style & Linting Compliance

We enforce strict automated formatting checks in our CI/CD pipelines. Ensure your changes comply before committing:

### Python Backend
Ensure you run formatters in the `/backend` folder:
- **Formatting (Black)**: `black backend/`
- **Import Sorting (Isort)**: `isort backend/`
- **Linting Checks (Ruff)**: `ruff check backend/`

### Frontend TypeScript
Ensure code matches prettier configurations:
- **Linting Check**: `npm run lint` inside `/frontend`

---

## 2. Git Branch Strategy & Workflow

We follow standard git-flow guidelines:
1. **Branch Names**:
   - For new capabilities: `feature/short-description`
   - For corrections: `bugfix/short-description`
   - For operations updates: `chore/short-description`
2. **Pull Requests Process**:
   - Rebase your branch with `main` frequently to resolve merge conflicts.
   - Run local validation test suites before pushing code.

---

## 3. Testing Policy

Any new feature additions must be accompanied by appropriate test coverage:
- **Backend Tests**: Create pytest modules inside `/backend/tests`. Ensure negative behavior boundary cases are fully covered.
- **Frontend Tests**: Add Vitest files inside `__tests__` directories validating rendering structures and redirects.

---

## 4. Code Review Checklist

Before marking a Pull Request as ready for review, check that:
- [ ] Code follows SOLID principles and clean architecture standards.
- [ ] No secrets, private credentials, or private access tokens are hardcoded.
- [ ] Standard logging formatting and trace annotations are used.
- [ ] All unit tests pass cleanly.
