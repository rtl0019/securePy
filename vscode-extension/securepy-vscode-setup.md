# SecurePy VS Code Extension – Setup Summary

## 1. Clone the Repository

Cloned the existing SecurePy Python security scanner project from GitHub to use as the backend CLI tool for the VS Code extension.

**Tools used:** Git, GitHub

---

## 2. Set Up Python Environment

Created a Python virtual environment and installed the SecurePy package in editable mode so the CLI tool could be run locally.

**Steps:**
- Created virtual environment with Python 3.12
- Activated virtual environment
- Upgraded pip, setuptools, wheel
- Installed SecurePy with:

```bash
pip install -e .
```

**Tools used:** Python 3.12, pip, venv

---

## 3. Generate VS Code Extension Template

Used the Yeoman VS Code extension generator to create the extension scaffold.

**Command used:**

```bash
npx --package yo --package generator-code -- yo code
```

**Selected options:**
- TypeScript extension
- Unbundled
- npm package manager

**This created:**
- `package.json`
- `tsconfig.json`
- `extension.ts`
- Compile scripts
- Test framework
- VS Code launch configs

**Tools used:** Node.js, npm, Yeoman, generator-code, TypeScript

---

## 4. Compile Extension

Compiled TypeScript into JavaScript so VS Code could run the extension.

**Command:**

```bash
npm run compile
```

**Tools used:** TypeScript compiler (tsc), npm scripts

---

## 5. Implement Extension Logic

Modified `extension.ts` to add the following features:

- Register commands
- Run SecurePy CLI using `execFile`
- Capture JSON output
- Parse findings
- Create VS Code diagnostics
- Highlight issues in editor
- Add scan workspace command
- Add scan on save feature
- Add clear diagnostics command
- Add extension settings (executable path, scan args, scan on save)

**VS Code APIs used:**
- `commands.registerCommand`
- `window.createOutputChannel`
- `languages.createDiagnosticCollection`
- `workspace.onDidSaveTextDocument`
- `Diagnostic`
- `DiagnosticSeverity`
- `Range`
- `Uri`

**Technologies used:** TypeScript, VS Code Extension API, Node.js child_process

---

## 6. Modify SecurePy for JSON Stdout Support

Updated SecurePy Python CLI so JSON reports could be printed to stdout instead of writing to a file (fix for read-only filesystem issue in VS Code extension).

**Added:**
- `--stdout` option
- JSON reporter writing to stdout
- Extension reads stdout JSON and converts findings into diagnostics

**Tools used:** Python, argparse, JSON, CLI design

---

## 7. Package the Extension

Installed VS Code Extension packaging tool and built a `.vsix` package.

**Commands:**

```bash
npm install -g vsce
vsce package
```

**Tools used:** vsce (Visual Studio Code Extension CLI), npm

---

## 8. Publish Extension to VS Code Marketplace

**Created:**
- Azure DevOps account
- Marketplace publisher
- Personal Access Token (PAT)
- Logged into vsce
- Published extension

**Commands:**

```bash
vsce login <publisher>
vsce publish
```

**Tools used:** Azure DevOps, VS Code Marketplace, Personal Access Token, vsce

---

## 9. Git Workflow and Contribution

Forked the SecurePy repository and contributed changes via Git workflow.

**Steps:**
- Fork repository
- Add upstream remote
- Create branch `vsc-ext`
- Commit SecurePy JSON stdout changes
- Push branch to fork
- Open pull request to original repository

**Git commands used:**

```bash
git clone
git checkout -b
git add
git commit
git push
git remote add upstream
git remote set-url origin
git push -u origin vsc-ext
```

**Tools used:** Git, GitHub, Pull Requests, Forking workflow

---

## Technologies Used Overall

### Languages
- Python
- TypeScript
- JavaScript
- JSON

### Tools & Platforms
- Git
- GitHub
- VS Code Extension API
- Node.js
- npm
- Yeoman
- TypeScript compiler
- Python venv
- Azure DevOps
- VS Code Marketplace
- vsce

### Concepts
- CLI tool integration
- Static analysis tooling
- VS Code diagnostics API
- Editor extensions
- JSON reporting pipelines
- Git branching and pull requests
- Packaging and publishing software
- Scan on save automation
- Workspace scanning

---

## Final Result

Built and published a VS Code extension that:

- Runs SecurePy static security scans
- Scans files or entire workspace
- Highlights security issues in editor
- Adds issues to Problems panel
- Supports scan on save
- Configurable executable path and arguments
- Published to VS Code Marketplace
