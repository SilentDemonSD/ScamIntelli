---
agent: "agent"
description: "Generate a production-grade Python coding standards document strictly following PEP 8, snake_case naming, and async-first architecture based on the provided file(s) or folder(s)."
tools: ['edit/createFile', 'edit/editFiles', 'web/fetch', 'web/githubRepo', 'search', 'execute/testFailure']
---

# Generate Python Async Production Coding Standards (PEP 8 Strict)

Analyze the provided Python file(s) and generate a professional coding standards document aligned with:

- PEP 8
- snake_case naming conventions
- Async-first programming
- Production-ready architecture
- High performance and scalability
- Strict typing
- Clean code principles
- No inline comments in production code examples

If multiple files or a folder are provided:
- Aggregate patterns.
- Detect dominant formatting style.
- Use majority style as base.
- Do not auto-fix inconsistencies unless enabled.

---

## Required Parameter

- fileName (required)

## Optional Parameters

- folderName
- instructions
- useTemplate = ["verbose", "minimal", "best", "custom"]
- outputSpecToPrompt = true | false
- createNewFile = true | false
- addToREADME = true | false
- addStandardsTest = true | false
- fixInconsistencies = true | false

---

# Core Standards (PEP 8 + Async Enforced)

## 1. Python Version

- Python 3.11+
- UTF-8 encoding
- One newline at end of file
- Maximum line length: 100 characters

---

## 2. Naming Conventions (Strict snake_case)

| Item | Convention |
|------|------------|
| Variables | lower_snake_case |
| Functions | lower_snake_case |
| Async Functions | async def lower_snake_case |
| Classes | PascalCase |
| Constants | UPPER_SNAKE_CASE |
| Modules | lower_snake_case |
| Private Members | _leading_underscore |

No camelCase allowed.

---

## 3. Formatting (PEP 8 Strict)

- 4 spaces indentation
- One blank line between logical blocks
- Two blank lines between top-level classes/functions
- One space around operators
- Imports grouped:
  1. Standard library
  2. Third-party
  3. Local modules
- No wildcard imports
- No unused imports
- No circular imports

---

## 4. Async-First Architecture

- All IO-bound operations must use async
- No blocking calls inside async functions
- Use asyncio-compatible libraries
- Use await properly
- Avoid mixing sync and async in same layer
- Thread pools only when unavoidable
- Prefer asyncio.gather for concurrency
- No global mutable state

---

## 5. Type Safety

- All functions must include type hints
- Return types mandatory
- Avoid Any
- Use built-in generics (list[str], dict[str, int])
- Use dataclasses or Pydantic models for structured data
- Use Protocol where applicable

---

## 6. Architecture Guidelines

- Clear separation:
  - api/
  - services/
  - domain/
  - infrastructure/
  - core/
- No business logic in route handlers
- Dependency injection preferred
- Configuration isolated
- No hidden side effects

---

## 7. Performance Rules

- Prefer comprehensions over manual loops
- Use set/dict lookup for O(1) operations
- Avoid unnecessary allocations
- Use generators for streaming
- Lazy load heavy modules
- Avoid redundant awaits
- Avoid nested loops when index structures can be used

---

## 8. Error Handling

- No bare except
- Catch specific exceptions
- No silent failures
- Raise domain-specific exceptions
- Structured logging only
- Do not print in production code

---

## 9. Documentation Rules

- Public functions require docstrings
- Use triple double quotes
- No redundant inline comments
- Code must be self-explanatory
- No commented-out code

---

## 10. Testing Standards

- pytest required
- Async tests must use pytest-asyncio
- Deterministic tests
- No sleep-based timing
- Minimum 80% coverage

---

## 11. Tooling Enforcement

- ruff (linting)
- mypy --strict
- black (line length 100)
- isort
- pre-commit hooks

---

## Inconsistency Handling

If findInconsistencies == true:
- Detect:
  - Mixed naming styles
  - Missing type hints
  - Sync functions in async layers
  - Improper import ordering
  - Line length violations

If fixInconsistencies == true:
- Normalize to dominant PEP 8 style

Else:
- Output inconsistency report only

---

## File Creation Rules

If createNewFile == true:
Create first non-existing file from:

- CODING_STANDARDS.md
- PROJECT_STANDARDS.md
- BEST_PRACTICES.md
- CONTRIBUTING.md

If outputSpecToPrompt == true:
Output standards in prompt only.

If addToREADME == true:
Insert before end of README.md.

---

## Template Modes

### verbose
Full enterprise-grade standards including:
- Async architecture
- Performance optimization
- Security
- CI/CD enforcement
- Toolchain config examples

### minimal
Concise strict PEP 8 async rules.

### best
Auto-select based on project complexity.

### custom
Follow additional instructions provided.

---

## Code Example Requirements

When generating example code:
- Must follow PEP 8
- Must use snake_case
- Must use async where IO-bound
- Must include type hints
- Must not include inline comments
- Must not include debug prints
- Must not include unused variables

---

Generate a strict, production-grade, async-first Python coding standards document fully compliant with PEP 8.
