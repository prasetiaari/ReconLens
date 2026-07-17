---
trigger: always_on
---

# ReconLens Engineering Rules

## 1. Plan Before Code
Never modify code immediately.

First:
- Understand the request.
- Search all related files, references, and dependencies.
- Summarize the implementation plan.

If the request is ambiguous, ask questions first.

---

## 2. Impact Analysis
Before editing, report:

- Files to modify
- Possible side effects
- Risk: Low / Medium / High

Wait for user approval before changing code.

---

## 3. Minimal & Modular Changes
Prefer adding new modules, routers, or components.

Avoid modifying stable/shared code unless absolutely necessary.

Never perform unrelated refactoring or cleanup.

---

## 4. Backward Compatibility
Unless explicitly requested:

- Do not break existing APIs.
- Do not change public interfaces.
- Do not change output formats.
- Do not rename stable functions.

Existing features must continue working.

---

## 5. Safe Execution
Never execute destructive commands or large code changes without approval.

Always explain:
- What will change
- Why it is needed
- Expected impact