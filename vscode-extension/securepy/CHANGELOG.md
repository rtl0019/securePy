# Changelog

All notable changes to the **SecurePy VS Code Extension** will be documented in this file.

This project adheres to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] – Initial Release

### Added

#### VS Code Extension
- Register and expose extension commands via VS Code Command Palette
- Run SecurePy CLI as a subprocess using Node.js `execFile`
- Capture and parse JSON output from SecurePy CLI
- Convert parsed findings into native VS Code `Diagnostic` objects
- Highlight security issues inline in the editor
- Surface issues in the VS Code Problems panel
- **Scan File** command – scan the currently active file
- **Scan Workspace** command – scan all Python files in the workspace
- **Clear Diagnostics** command – remove all SecurePy diagnostics from the editor
- **Scan on Save** – automatically trigger a scan whenever a Python file is saved
- Extension settings:
  - `securepy.executablePath` – path to the SecurePy CLI executable
  - `securepy.scanArgs` – additional arguments passed to the CLI
  - `securepy.scanOnSave` – enable/disable automatic scan on save

#### SecurePy CLI (Backend)
- Added `--stdout` flag to print JSON reports to stdout instead of writing to a file
- Added JSON reporter that writes structured findings directly to stdout
- Resolves read-only filesystem compatibility issue when running inside VS Code

#### Packaging & Publishing
- Packaged extension as a `.vsix` file using `vsce`
- Published extension to the VS Code Marketplace
- Created Azure DevOps publisher account and Personal Access Token (PAT) for marketplace authentication

#### Repository & Git Workflow
- Forked SecurePy repository to support upstream contribution
- Created `vsc-ext` branch for all extension-related backend changes
- Opened pull request to upstream SecurePy repository with JSON stdout changes