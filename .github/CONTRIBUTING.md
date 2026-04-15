# Contributing to SEER Sensor

Welcome to the SEER Sensor project. This guide covers everything you need to set up your environment and start contributing.

## Required Reading

Before contributing, review the EVR:RDY policies that govern this project:

- **[Git Workflow Policy](https://github.com/EVR-RDY-Projects/evrrdy-mcp-internal/blob/main/policy/development/git-workflow-policy.md)** — Branching, commits, PRs
- **[Code Review Standards](https://github.com/EVR-RDY-Projects/evrrdy-mcp-internal/blob/main/policy/development/code-review-standards.md)** — Review requirements
- **[Python Coding Standards](https://github.com/EVR-RDY-Projects/evrrdy-mcp-internal/blob/main/policy/development/coding-standards/python-language/README.md)** — Google Python Style Guide (Ruff enforced)
- **[Testing Standards](https://github.com/EVR-RDY-Projects/evrrdy-mcp-internal/blob/main/policy/development/testing-standards.md)** — 85% coverage requirement
- **[Security Policy](https://github.com/EVR-RDY-Projects/evrrdy-mcp-internal/blob/main/policy/security/security-policy.md)** — Security requirements
- **[Definition of Done](https://github.com/EVR-RDY-Projects/evrrdy-mcp-internal/blob/main/policy/development/definition-of-done.md)** — Completion criteria
- **[AI/LLM Development Policy](https://github.com/EVR-RDY-Projects/evrrdy-mcp-internal/blob/main/policy/development/ai-llm-development-policy.md)** — AI usage requirements (MUST READ)

> **Note**: The policy repo is private. You will be granted read access when onboarded as a contributor.

## Prerequisites

- GitHub account with [commit signing configured](#commit-signing-setup)
- Git installed locally
- Python 3.11+
- ShellCheck (for linting bash scripts)

## Getting Started

### 1. Fork the Repository

1. Go to [EVR-RDY-Projects/SEER-Sensor](https://github.com/EVR-RDY-Projects/SEER-Sensor)
2. Click **Fork** (top-right)
3. Clone your fork:

```bash
git clone git@github.com:YOUR_USERNAME/SEER-Sensor.git
cd SEER-Sensor
```

4. Add the upstream remote:

```bash
git remote add upstream git@github.com:EVR-RDY-Projects/SEER-Sensor.git
git fetch upstream
```

### 2. Commit Signing Setup

All commits **must** be signed. Unsigned commits will be rejected by our repository rulesets. We recommend SSH signing (simplest setup).

#### SSH Signing (Recommended)

**a) Configure Git to sign with SSH:**

```bash
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/YOUR_KEY.pub
git config --global commit.gpgsign true
git config --global tag.gpgsign true
```

**b) Create an allowed signers file (for local verification):**

```bash
echo "YOUR_EMAIL $(cat ~/.ssh/YOUR_KEY.pub)" > ~/.ssh/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers
```

**c) Upload your public key to GitHub as a signing key:**

1. Go to [GitHub SSH Keys Settings](https://github.com/settings/keys)
2. Click **New SSH Key**
3. Set **Key type** to **Signing Key**
4. Paste the contents of your `~/.ssh/YOUR_KEY.pub`
5. Save

> **Important**: Authentication keys and signing keys are separate on GitHub. You need to upload your key as a **signing key** even if it's already added as an authentication key.

**d) Verify signing works:**

```bash
git commit --allow-empty -m "test: verify signing"
git log --show-signature -1
```

You should see `Good "git" signature for your@email.com`.

> ⚠️ **Already committed before setting up signing?** Those commits are unsigned and the PR merge will fail. After configuring signing, resign them:
>
> ```bash
> git rebase --exec 'git commit --amend --no-edit -S' HEAD~N
> git push --force-with-lease
> ```
>
> Replace `N` with the number of unsigned commits on your branch. Verify with `git log --show-signature`.

### 3. Install Linting Tools

Our CI runs these checks on every PR. Install them locally to catch issues early:

```bash
# Python linters and SAST
pip install ruff yamllint bandit

# ShellCheck (macOS)
brew install shellcheck

# ShellCheck (Ubuntu/Debian)
sudo apt-get install shellcheck
```

Run all linters locally before pushing:

```bash
ruff check .
ruff format --check .
yamllint -c .yamllint.yaml .
shellcheck --shell=bash --severity=warning Automation/install.sh Automation/seer-zeek.sh Automation/bin/*.sh
find . -name '*.py' -not -path './.git/*' -exec python -m py_compile {} +
bandit -r Automation/ --ini .bandit -f txt
```

## Workflow

### Branch Naming Convention (Enforced)

All feature branches **must** follow this pattern:

```
type/your-github-username/short-description
```

**Allowed types:** `feat`, `fix`, `hotfix`, `chore`, `refactor`

> ⚠️ Use `feat/` — **not** `feature/`. Our ruleset rejects `feature/...` branches. The regex is strict: `^(feat|fix|hotfix|chore|refactor)/[a-zA-Z0-9_-]+/[a-z0-9][a-z0-9-]+$`.

**Examples:**

```bash
feat/johndoe/python-config-parser
fix/johndoe/hotswap-race-condition
chore/johndoe/update-dependencies
refactor/johndoe/move-oldest-to-class
```

### Commit Message Convention (Enforced)

All commits **must** use [Conventional Commits](https://www.conventionalcommits.org/) format:

```
type(optional-scope): description
```

**Allowed types:** `feat`, `fix`, `hotfix`, `chore`, `refactor`, `docs`, `test`, `ci`, `perf`, `style`, `build`

**Examples:**

```bash
feat: add config file parser in Python
fix: handle empty pcap directory gracefully
docs: add inline comments to move_oldest.py
refactor: convert move_oldest.sh to Python class
test: add unit tests for config parser
chore: update ruff lint rules
```

**Invalid (will be rejected):**

```bash
Updated stuff
WIP
misc fixes
Add feature
```

### Creating a Pull Request

1. Sync your fork with upstream:

```bash
git fetch upstream
git checkout development
git merge upstream/development
```

2. Create your feature branch:

```bash
git checkout -b feat/your-username/description
```

3. Make your changes, commit (signed + conventional message), push to your fork:

```bash
git add <files>
git commit -m "feat: description of change"
git push origin feat/your-username/description
```

4. Open a PR on GitHub:
   - **Base:** `EVR-RDY-Projects/SEER-Sensor` → `development`
   - **Compare:** `your-fork` → `feat/your-username/description`
   - Fill in the PR description with what you changed and why

5. Wait for CI to pass (7 checks) and code review from a maintainer.

### What Gets Checked

Every PR runs these CI checks (all must pass):

| Check | What it does |
|-------|-------------|
| ShellCheck | Lints bash scripts for errors and warnings |
| Ruff (lint + format) | Python linting and format checking |
| yamllint | YAML file validation |
| Python syntax check | Compiles all .py files |
| Python dependency validation | Verifies scout_receiver imports |
| Bandit (SAST) | Python security scanning (injection, crypto, etc.) |
| Blocked file extensions | Rejects secrets (.env, .pem, .key) and binaries (.exe, .pyc, etc.) |

### Merge Strategy

- PRs to `development` use **merge commits** (preserves your commit history)
- PRs to `main` use **squash merge** (clean single-commit history)
- You will always target `development` — merges to `main` are handled by maintainers

## Blocked File Extensions

The following file types **cannot** be committed (CI will reject them):

**Secrets:** `.env`, `.pem`, `.key`, `.p12`, `.pfx`, `.credentials`, `.secret`

**Binaries:** `.exe`, `.dll`, `.so`, `.o`, `.pyc`, `.bin`, `.iso`, `.img`, `.jar`, `.war`

## Project Structure

```
SEER-Sensor/
├── Automation/
│   ├── bin/                  # Runtime scripts (bash + Python)
│   │   ├── seer-capture.sh   # PCAP capture via tcpdump
│   │   ├── seer_console.py   # Curses TUI console
│   │   ├── seer_terminal.sh  # Terminal wrapper
│   │   ├── seer-verify-install.sh
│   │   ├── seer-wait-link.sh
│   │   └── seer_uninstall.sh
│   ├── SEER/                 # Python modules
│   │   ├── move_oldest.py    # PCAP mover (oldest-out)
│   │   ├── seer_hotswap.py   # Hot-swap drive manager
│   │   ├── setup_wizard.py   # Interactive setup
│   │   └── scout_receiver/   # HTTP data receiver (aiohttp)
│   ├── systemd/              # systemd service files
│   ├── install.sh            # Main installer
│   └── seer-zeek.sh          # Zeek launcher
├── Hardware/
│   └── POC/                  # Hardware proof-of-concept docs
├── .github/
│   ├── workflows/ci.yml      # CI pipeline
│   └── CODEOWNERS            # Review requirements
├── pyproject.toml             # Ruff config (Python 3.11, line-length 80)
├── .yamllint.yaml             # yamllint config
└── ROADMAP.md                 # Project milestones
```

## Code Style

- **Python**: Ruff enforced. Line length 80 (Google Python Style). Import sorting enabled. Target Python 3.11. Bandit SAST scanning on all Python code.
- **Bash**: ShellCheck enforced at warning severity. All scripts use `#!/usr/bin/env bash`.
- **YAML**: yamllint enforced. Document start (`---`) required. Max line length 160.

## Troubleshooting

Before reaching out, try these diagnostics. Most "permission" or "access" issues are one of the scenarios below.

### Check your remotes

```bash
git remote -v
```

Expected:

```text
origin    git@github.com:YOUR_USERNAME/SEER-Sensor.git (fetch)
origin    git@github.com:YOUR_USERNAME/SEER-Sensor.git (push)
upstream  git@github.com:EVR-RDY-Projects/SEER-Sensor.git (fetch)
upstream  git@github.com:EVR-RDY-Projects/SEER-Sensor.git (push)
```

If `origin` points to `EVR-RDY-Projects/SEER-Sensor`, you cloned upstream directly instead of your fork. Fix:

```bash
git remote set-url origin git@github.com:YOUR_USERNAME/SEER-Sensor.git
```

### Check commit signatures

```bash
git log --show-signature -1
```

Must say `Good "ssh" signature`. If it says `no signature` or the commit has no signature block, your git signing isn't active — revisit [§2 Commit Signing Setup](#2-commit-signing-setup).

### Common errors

| Error | Cause | Fix |
|---|---|---|
| `Permission denied (publickey)` on push | SSH key not added to GitHub, or wrong key loaded | `ssh -T git@github.com` to test auth; add key to GitHub; `ssh-add ~/.ssh/YOUR_KEY` |
| `remote: Permission to EVR-RDY-Projects/SEER-Sensor.git denied` | You pushed to upstream. Triage role cannot push to upstream. | Fix `origin` to point to your fork (see above) |
| PR shows "commits are not signed" | Signing configured after committing | Rebase-amend-sign (see signing §2 warning) |
| `gh pr create` fails with auth error | `gh` CLI not authenticated | `gh auth login` |
| PR targets `main` and won't merge | External PRs must target `development` | Edit PR base in GitHub UI: click "Edit" next to title, change base to `development` |

### Fork default branch

Your fork's default branch is whatever upstream's default was when you forked. Our default is `development`, and all external PRs target `development`. When using GitHub's "Compare & pull request" banner, verify **base: development** before submitting.

If your fork still shows `main` as default (older fork), you can change it in your fork's settings: **Settings → Branches → Default branch → development**.

## Questions?

Open an issue on the repository or reach out to the maintainers.
