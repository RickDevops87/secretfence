<p align="center">
  <h1 align="center">secretfence</h1>
  <p align="center"><strong>Your AI coding assistant can read your <code>.env</code> file. secretfence stops it.</strong></p>
  <p align="center">
    <a href="#quick-start">Quick Start</a> |
    <a href="#three-layers-of-protection">How It Works</a> |
    <a href="#how-it-compares">Comparison</a> |
    <a href="#configuration">Config</a>
  </p>
</p>

---

A Rust CLI that detects secrets in your project and reduces their exposure to AI coding tools through ignore-file generation, Claude Code pre-tool checks, and a macOS process sandbox.

Fully local. No accounts. No API calls. Everything runs on your machine.

## The Problem

Every AI coding tool has full filesystem access. Your `.env`, your private keys, your deploy secrets &mdash; all of it goes into the context window. The ecosystem response so far:

| Tool | What it does | Fully local? | Enforced? |
|------|-------------|:---:|:---:|
| `.cursorignore` / `.claudeignore` / etc. | Ask the AI nicely not to read files | Yes | No &mdash; agent mode bypasses via shell |
| [aiignore-cli](https://github.com/yjcho9317/aiignore-cli) | Generate ignore files for all tools | Yes | No &mdash; same bypass problem |
| [ggshield ai-hook](https://github.com/GitGuardian/ggshield) | Real-time hook scanning | **No** &mdash; requires GitGuardian API | Partial |
| [.llmignore](https://github.com/llmignore-spec/llmignore-spec) | Universal ignore file spec | Yes | No &mdash; nothing enforces it |
| Secret managers (1Password, Vault) | Remove secrets from disk | Yes | Yes &mdash; but requires infra changes |

**The gap:** Most local ignore files are advisory. Secretfence adds local scanning and, on macOS, an OS-level filesystem boundary for processes it launches.

## Three Layers of Protection

```
  Layer 1: SCAN            Layer 2: CLAUDE HOOK      Layer 3: macOS SANDBOX
 ──────────────────       ──────────────────        ──────────────────
  Detect secrets           Check tool payloads       Process isolation
  Generate ignore files    Block matched access      Deny configured file reads
  Verify live secrets      Claude Code only          macOS only

  sf scan --fix            sf hook install           sf exec -- claude
```

Each layer works independently. Use one, two, or all three.

## Quick Start

```bash
# Install (downloads prebuilt binary to /usr/local/bin)
curl -sSL https://raw.githubusercontent.com/solhosty/secretfence/main/install.sh | sh

# Or build from source
cargo install secretfence

# Scan your project for exposed secrets
sf scan

# Auto-generate ignore files for all detected AI tools
sf scan --fix

# Verify which detected secrets are actually live
sf scan --verify

# Install Claude Code's PreToolUse hook (and an advisory Cursor rule when applicable)
sf hook install

# Run your AI tool in a sandboxed process
sf exec -- claude
```

---

## Layer 1: Scan + Generate

Detect secret files and content patterns across your project.

```
$ sf scan

  secretfence scanning project...

  SECRET FILES:

  .env                           Environment variable files
  foundry.toml                   Foundry configuration (may contain RPC URLs with keys)
  hardhat.config.ts              Hardhat configuration (may contain private keys)

  CONTENT MATCHES:

  .env:1                         Database Connection String
  .env:2                         Ethereum private key (64 hex chars)
  .env:4                         AWS Secret Access Key
  src/config.ts:1                Google API Key
  src/config.ts:2                Slack Bot/User/Workspace Token

  Found 8 secrets in 4 files.

  Run sf scan --fix to generate ignore files for your AI tools.
```

Auto-generate the right ignore config for every AI tool:

```
$ sf scan --fix

  Generated ignore rules for:
    Claude Code     .claude/settings.json (62 deny rules added)
    Cursor          .cursorignore (62 patterns added)
    Gemini CLI      .geminiignore (62 patterns added)
    Universal       .llmignore (62 patterns added)
```

### Supported AI Tools

| AI Tool | Ignore Format | `scan --fix` | `hook install` |
|---------|:-------------|:---:|:---:|
| Claude Code | `.claude/settings.json` | Yes | Yes — executable `PreToolUse` hook |
| Cursor | `.cursorignore` | Yes | Advisory project rule only |
| Gemini CLI | `.geminiignore` | Yes | Not implemented |
| JetBrains AI | `.aiignore` | Yes | Planned |
| Windsurf | `.codeiumignore` | Yes | Planned |
| Aider | `.aiderignore` | Yes | Planned |
| GitHub Copilot | *(no ignore file)* | N/A | Planned |
| Universal | `.llmignore` | Yes | N/A |

---

## Layer 2: Hook Scanning

`sf hook install` installs an executable `PreToolUse` hook for Claude Code. It checks matching Claude Code tool payloads before execution. If a project already has `.cursor/`, it also writes an advisory Cursor rule; Cursor does not expose an executable hook through this integration, so that rule is not enforcement.

```
$ sf hook install

  Installing secretfence hooks...

    Claude Code     PreToolUse hook installed
    Cursor          advisory project rule installed
```

When the AI tries to read a secret:

```
[secretfence] BLOCKED: Read access to .env
  Rule: dotenv — Environment variable files
```

All pattern matching runs locally. Nothing leaves your machine.

---

## Layer 3: Process Sandbox

On macOS, run an AI tool inside a Seatbelt sandbox that denies configured file reads. Even `cat .env` through a shell command is denied by the kernel. On Linux and Windows, `sf exec` only scrubs matching environment variables; it does not enforce the deny-path list.

```bash
sf exec -- claude                              # Auto-detect secrets, sandbox the process
sf exec --profile web3 -- cursor               # Use a preset profile
sf exec --deny .env,.env.local -- claude        # Explicit deny list
sf exec --dry-run -- claude                     # Preview sandbox config
```

**Proof it works:**

```
$ sf exec --deny .env -- cat .env

  secretfence Starting sandboxed process...

    deny /path/to/project/.env

cat: .env: Operation not permitted
```

### Platform Support

| Platform | Mechanism | Enforcement Level |
|:---------|:----------|:------------------|
| **macOS** | `sandbox-exec` (Seatbelt profiles) | Kernel-enforced for configured paths |
| **Linux** | Environment-variable scrubbing | Best-effort; deny paths are not enforced |
| **Windows** | Environment-variable scrubbing | Best-effort; deny paths are not enforced |

On macOS, a process launched through `sf exec` receives `EPERM` for configured paths regardless of which binary tries the read &mdash; `cat`, `python`, `node`, or the AI tool itself. This boundary only covers that launched process and its children.

---

## Secret Verification

Opt-in live validation checks whether detected secrets are actually active credentials. **Requires network access** &mdash; off by default.

```
$ sf scan --verify

  secretfence Verifying detected secrets...

  ACTIVE SECRETS: (confirmed live credentials)
    LIVE .env                           GitHub Token — ACTIVE (ghp_Ab...xYz9)

  INACTIVE/REVOKED:
    dead src/config.ts                  Slack Token — inactive or revoked

  NOT VERIFIABLE: (4 secrets cannot be verified via API)

  Summary: 1 active, 1 inactive, 4 unverifiable, 0 errors
```

**Supported validators:**

| Secret Type | Validation Endpoint |
|:------------|:-------------------|
| GitHub Tokens | `GET /user` |
| Slack Tokens | `POST auth.test` |
| Stripe Keys | `GET /v1/charges?limit=1` |
| OpenAI Keys | `GET /v1/models` |
| Anthropic Keys | `GET /v1/models` |
| npm Tokens | `GET /-/whoami` |
| SendGrid Keys | `GET /v3/scopes` |

Secrets that don't match a known validator are marked "not verifiable" &mdash; they're still flagged by the scan, just not confirmed live.

---

## Profiles

Built-in presets for common ecosystems:

**`web3`** &mdash; Foundry, Hardhat, blockchain development:
```bash
sf exec --profile web3 -- claude
# Denies:  .env*, foundry.toml, hardhat.config.*, *.pem, mnemonic.txt
# Scrubs:  PRIVATE_KEY, MNEMONIC, DEPLOYER_*, ETHERSCAN_*, ALCHEMY_*, INFURA_*
```

**`generic`** &mdash; Common patterns across all ecosystems:
```bash
sf exec --profile generic -- claude
# Denies:  .env*, *.pem, *.key, credentials.*, secrets.*, terraform.tfvars
# Scrubs:  *_SECRET, *_KEY, *_TOKEN, *_PASSWORD, DATABASE_URL
```

Create custom profiles in `.secretfencerc`.

## Configuration

Create a `.secretfencerc` in your project root:

```toml
profile = "web3"

[rules]
extra_deny_paths = ["my-custom-secrets.yaml", "deploy-keys/"]
extra_deny_env = ["MY_APP_MASTER_KEY"]

[rules.allow]
paths = [".env.example", "test/fixtures/.env.test"]

[[rules.custom]]
id = "internal-api-key"
description = "Internal API key format"
regex = "INTERNAL_[A-Z]+_KEY=[A-Za-z0-9]{32}"
```

## Detection Rules

35+ content patterns and 17 path rule groups covering:

| Category | Examples |
|:---------|:--------|
| **Cloud** | AWS access keys, GCP service accounts, Azure storage keys |
| **Web3** | Private keys, mnemonics, RPC URLs, Etherscan/Alchemy/Infura keys |
| **Auth** | JWTs, OAuth tokens, Slack/Discord/Telegram bot tokens |
| **AI** | OpenAI, Anthropic, Linear API keys |
| **Databases** | Connection strings (Postgres, MySQL, MongoDB, Redis) |
| **Payments** | Stripe secret keys, SendGrid keys |
| **Infrastructure** | Terraform secrets, npm/PyPI tokens, SSH keys |
| **Certificates** | PEM, P12, PFX files |

All detection runs locally using precompiled regex. Custom rules via `.secretfencerc`.

---

## How It Compares

| | secretfence | ggshield ai-hook | aiignore-cli | .llmignore |
|:---|:---:|:---:|:---:|:---:|
| Fully local (no account) | **Yes** | No | Yes | Yes |
| Executable pre-tool hook | Claude Code | Yes | No | No |
| OS-level sandboxing | macOS only | No | No | No |
| Secret verification | **Yes** (opt-in) | Yes | No | No |
| Content pattern matching | 35+ rules | 500+ rules | No | No |
| File path detection | 17 rule groups | No | Yes | No |
| Ignore file generation | All tools | No | All tools | Single spec |
| Custom rules | `.secretfencerc` | GG dashboard | `.aiignorerc` | N/A |
| Requires account | **No** | Yes (free tier) | No | No |
| Language | Rust | Python | Node.js | Spec |

### Where ggshield wins

- 500+ patterns with years of false-positive tuning (ours are newer)
- GitHub Actions / pre-commit / CI integrations
- Validates secrets against live APIs by default (ours is opt-in)

### Where secretfence wins

- **Fully local** &mdash; no account, no API calls, no network access (unless `--verify`)
- **macOS sandboxing** &mdash; kernel-enforced file access denial for processes launched with `sf exec`
- **Single binary** &mdash; `cargo install` and go, no Python/pip/venv
- **Web3-native** &mdash; built-in profiles for Foundry, Hardhat, and blockchain development

---

## Contributing

Contributions welcome. Areas where help is most needed:

- Additional AI tool hook integrations
- Content detection rules for ecosystems we're missing
- Windows sandbox improvements (Job objects, restricted tokens)
- CI/CD integrations (GitHub Actions, pre-commit hooks)
- Linux filesystem sandboxing (Landlock or equivalent)

```bash
git clone https://github.com/solhosty/secretfence
cd secretfence
cargo build
cargo test
```

## License

MIT
