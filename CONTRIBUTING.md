# Contributing to PX Tunnel

Welcome! PX Tunnel is an open-source project from [PX Innovative Solutions Inc.](https://github.com/pxinnovative), and we're excited to build it with the community.

Whether you're fixing a typo, squashing a bug, or proposing a new feature — every contribution matters.

---

## How to Contribute

1. **Fork** this repository
2. **Create a branch** for your change:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Read the Code Rules below** — PRs that don't follow them will not be merged
4. **Make your changes** and test them locally
5. **Commit** with a clear message describing what and why
6. **Push** your branch and open a **Pull Request**

Please open an issue first if your change is significant — it helps avoid duplicate work and align on direction.

---

## Code Rules

These rules are **non-negotiable**. Every PR is reviewed against them. Code that doesn't follow these rules will be rejected regardless of what it does.

### 1. Zero Hard-Coding

**No magic numbers. No hardcoded paths. No unexplained constants.**

Every value that could change, that has meaning, or that appears more than once **must** be a named constant with a clear name.

```python
# BAD — what is 9999? what is 30000?
app.run(port=9999)
setTimeout(clearClipboard, 30000)

# GOOD — clear intent, easy to find and change
DEFAULT_PORT = 9999
CLIPBOARD_CLEAR_MS = 30000  # Auto-clear clipboard after copy

app.run(port=DEFAULT_PORT)
setTimeout(clearClipboard, CLIPBOARD_CLEAR_MS)
```

This applies to: ports, timeouts, dimensions, buffer sizes, file paths — **everything**.

### 2. No Secrets, No Personal Data

- Never commit API keys, tokens, passwords, or credentials
- Never hardcode usernames, email addresses, or internal paths
- Environment variables or config files for anything user-specific
- If you find a secret in the code, report it immediately (see [SECURITY.md](SECURITY.md))

### 3. Clear and Honest Code

PX Tunnel is a privacy-focused app. Users trust us with their most sensitive data. That trust is sacred.

- **No hidden behavior** — the code must do exactly what it says, nothing more
- **No telemetry, analytics, or tracking** — not even "anonymous" usage data
- **No network calls** — PX Tunnel must never phone home
- **No obfuscation** — code should be readable by anyone. If a reviewer can't understand what a function does in 30 seconds, it needs better naming or comments
- **Comments explain "why", not "what"** — the code itself should explain what it does

```python
# BAD — comment restates the code
x = x + 1  # increment x by 1

# GOOD — comment explains WHY
x = x + 1  # off-by-one fix for the 1-based index
```

### 4. Security First

- **No `shell=True`** in subprocess calls
- **No string interpolation** in shell commands — use list arguments
- **Escape all dynamic values** in HTML generation
- **Clean up temp files** with `try/finally` — never leave decrypted data on disk
- **Validate all file paths** before operations — especially anything from user input

### 5. Keep It Simple

- No unnecessary dependencies — PX Tunnel stays lightweight
- Prefer standard library over third-party when possible
- One function, one purpose — if a function does two things, split it
- No premature abstraction — three similar lines are better than a clever helper nobody understands

### 6. Test Locally

- Test your changes against a real Headscale instance
- Test in both browser and headless modes
- If your change affects the UI, test in both light and dark system themes
- If your change affects the CLI, test `--list`, `--get`, and piping output

### 7. Consistent Style

- Follow existing code patterns — don't introduce new conventions
- Constants at the top, in UPPER_SNAKE_CASE, grouped by section
- Classes and functions in logical order (helpers before callers)
- Docstrings on all public functions
- Type hints encouraged but not required

---

## What Makes a Good PR

- **Small and focused** — one feature or one fix per PR
- **Clear description** — explain what, why, and how to test
- **No unrelated changes** — don't "clean up" code you didn't need to touch
- **Screenshots** if it changes UI
- **Tested locally**

---

## Bug Reports

Found a bug? Open a [GitHub Issue](../../issues) with:

- What you expected to happen
- What actually happened
- Steps to reproduce
- Your OS, Python version, and Headscale version
- Console output or error messages

## Feature Requests

Have an idea? Open a [GitHub Issue](../../issues) with the `enhancement` label:

- The problem you're trying to solve
- Your proposed solution
- Any alternatives you've considered

---

## Code of Conduct

Be respectful. Be constructive. Be kind. We're building something together, and a welcoming community is the foundation. Harassment, trolling, or disrespectful behavior will not be tolerated.

## Contributor License Agreement

By submitting a PR, you agree that your contributions are licensed under AGPL-3.0, consistent with the project's license.

## Trademark

"PX Tunnel" is a trademark of PX Innovative Solutions Inc. If you fork this project, you must rename your version. See [TRADEMARK.md](TRADEMARK.md) for details.

## Contact

- **GitHub Issues** — preferred for bugs, features, and questions
- **Email** — github@pxinnovative.com

---

Thanks for contributing to PX Tunnel. Let's make secrets management free and private for everyone.
