import * as vscode from "vscode";
import { execFile } from "child_process";

type SecurePyIssue = {
  filename?: string;
  file?: string;
  path?: string;
  file_path?: string;
  line?: number;
  line_number?: number;
  column?: number | null;
  col?: number | null;
  message?: string;
  issue_text?: string;
  title?: string;
  severity?: string;
  confidence?: string;
  test_id?: string;
  rule_id?: string;
  remediation?: string;
};

type SecurePyJson = {
  issues?: SecurePyIssue[];
  results?: SecurePyIssue[];
  findings?: SecurePyIssue[];
};

let outputChannel: vscode.OutputChannel;
let diagnosticCollection: vscode.DiagnosticCollection;

class SecurePyQuickFixProvider implements vscode.CodeActionProvider {
  provideCodeActions(
    document: vscode.TextDocument,
    _range: vscode.Range,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    for (const diagnostic of context.diagnostics) {
      if (diagnostic.source !== "SecurePy") {
        continue;
      }

      const code = getDiagnosticCode(diagnostic);

      switch (code) {
        case "debug_mode":
        case "flask_debug_true":
          actions.push(createDebugFalseFix(document, diagnostic));
          break;

        case "unsafe_yaml_load":
        case "yaml_load":
          actions.push(createYamlSafeLoadFix(document, diagnostic));
          break;

        default:
          actions.push(createShowRuleHelpAction(code, diagnostic));
          break;
      }
    }

    return actions;
  }
}

function getDiagnosticCode(diagnostic: vscode.Diagnostic): string {
  if (typeof diagnostic.code === "string") {
    return diagnostic.code;
  }

  if (
    diagnostic.code &&
    typeof diagnostic.code === "object" &&
    "value" in diagnostic.code
  ) {
    return String(diagnostic.code.value);
  }

  return "securepy";
}

function createDebugFalseFix(
  document: vscode.TextDocument,
  diagnostic: vscode.Diagnostic
): vscode.CodeAction {
  const action = new vscode.CodeAction(
    "Change debug=True to debug=False",
    vscode.CodeActionKind.QuickFix
  );

  action.diagnostics = [diagnostic];
  action.isPreferred = true;

  const line = document.lineAt(diagnostic.range.start.line);
  if (!line.text.includes("debug=True")) {
    return action;
  }

  const newLine = line.text.replace("debug=True", "debug=False");

  const edit = new vscode.WorkspaceEdit();
  edit.replace(document.uri, line.range, newLine);
  action.edit = edit;

  return action;
}

function createYamlSafeLoadFix(
  document: vscode.TextDocument,
  diagnostic: vscode.Diagnostic
): vscode.CodeAction {
  const action = new vscode.CodeAction(
    "Replace yaml.load with yaml.safe_load",
    vscode.CodeActionKind.QuickFix
  );

  action.diagnostics = [diagnostic];
  action.isPreferred = true;

  const line = document.lineAt(diagnostic.range.start.line);
  if (!line.text.includes("yaml.load")) {
    return action;
  }

  const newLine = line.text.replace("yaml.load", "yaml.safe_load");

  const edit = new vscode.WorkspaceEdit();
  edit.replace(document.uri, line.range, newLine);
  action.edit = edit;

  return action;
}

function createShowRuleHelpAction(
  code: string,
  diagnostic: vscode.Diagnostic
): vscode.CodeAction {
  const action = new vscode.CodeAction(
    `SecurePy: Explain rule "${code}"`,
    vscode.CodeActionKind.QuickFix
  );

  action.diagnostics = [diagnostic];
  action.command = {
    command: "securepy.explainRule",
    title: "Explain SecurePy rule",
    arguments: [code]
  };

  return action;
}

export function activate(context: vscode.ExtensionContext) {
  outputChannel = vscode.window.createOutputChannel("SecurePy");
  diagnosticCollection = vscode.languages.createDiagnosticCollection("securepy");

  const scanFileCommand = vscode.commands.registerCommand("securepy.scanFile", async () => {
    const editor = vscode.window.activeTextEditor;

    if (!editor) {
      vscode.window.showErrorMessage("No active file open.");
      return;
    }

    const document = editor.document;

    if (document.isUntitled) {
      vscode.window.showErrorMessage("Please save the file before scanning.");
      return;
    }

    if (!isPythonDocument(document)) {
      vscode.window.showWarningMessage("SecurePy only scans Python files.");
      return;
    }

    await runSecurePyScan([document.fileName], getScanCwdForDocument(document));
  });

  const scanWorkspaceCommand = vscode.commands.registerCommand("securepy.scanWorkspace", async () => {
    const workspaceFolder = vscode.workspace.workspaceFolders?.[0];

    if (!workspaceFolder) {
      vscode.window.showErrorMessage("No workspace folder is open.");
      return;
    }

    await runSecurePyScan([workspaceFolder.uri.fsPath], workspaceFolder.uri.fsPath);
  });

  const clearDiagnosticsCommand = vscode.commands.registerCommand("securepy.clearDiagnostics", () => {
    diagnosticCollection.clear();
    outputChannel.appendLine("SecurePy diagnostics cleared.");
    vscode.window.showInformationMessage("SecurePy diagnostics cleared.");
  });

  const explainRuleCommand = vscode.commands.registerCommand("securepy.explainRule", async (code: string) => {
    vscode.window.showInformationMessage(
      `SecurePy rule: ${code}. Add richer rule documentation or a docs URL here later.`
    );
  });

  const quickFixProvider = vscode.languages.registerCodeActionsProvider(
    { language: "python", scheme: "file" },
    new SecurePyQuickFixProvider(),
    {
      providedCodeActionKinds: [vscode.CodeActionKind.QuickFix]
    }
  );

  const scanOnSaveDisposable = vscode.workspace.onDidSaveTextDocument(async (document) => {
    const config = vscode.workspace.getConfiguration();
    const scanOnSave = config.get<boolean>("securepy.scanOnSave", false);

    if (!scanOnSave) {
      return;
    }

    if (!isPythonDocument(document)) {
      return;
    }

    if (document.isUntitled) {
      return;
    }

    outputChannel.appendLine(`Scan-on-save triggered for: ${document.fileName}`);
    await runSecurePyScan([document.fileName], getScanCwdForDocument(document), false);
  });

  context.subscriptions.push(
    scanFileCommand,
    scanWorkspaceCommand,
    clearDiagnosticsCommand,
    explainRuleCommand,
    quickFixProvider,
    scanOnSaveDisposable,
    outputChannel,
    diagnosticCollection
  );
}

export function deactivate() {}

async function runSecurePyScan(
  targets: string[],
  cwd?: string,
  showOutput: boolean = true
): Promise<void> {
  const config = vscode.workspace.getConfiguration();
  const configuredExecutablePath = (config.get<string>("securepy.executablePath", "") ?? "").trim();
  const extraArgs = config.get<string[]>("securepy.scanArgs", [
    "--format",
    "json",
    "--stdout",
    "--no-color"
  ]);

  const directArgs = ["scan", ...targets, ...extraArgs];
  const pythonModuleArgs = ["-m", "securepy", "scan", ...targets, ...extraArgs];

  const commandsToTry: Array<{ command: string; args: string[]; label: string }> = [];

  if (configuredExecutablePath.length > 0) {
    commandsToTry.push({
      command: configuredExecutablePath,
      args: directArgs,
      label: configuredExecutablePath
    });
  }

  commandsToTry.push(
    {
      command: "python3",
      args: pythonModuleArgs,
      label: "python3 -m securepy"
    },
    {
      command: "python",
      args: pythonModuleArgs,
      label: "python -m securepy"
    }
  );

  outputChannel.clear();

  if (showOutput) {
    outputChannel.show(true);
  }

  let lastError: Error | null = null;
  let combinedStderr = "";

  for (const attempt of commandsToTry) {
    outputChannel.appendLine(`Running: ${attempt.label} ${attempt.args.join(" ")}`);
    outputChannel.appendLine("");

    const result = await execFileAsync(attempt.command, attempt.args, cwd);

    if (result.stderr?.trim()) {
      outputChannel.appendLine("stderr:");
      outputChannel.appendLine(result.stderr);
      outputChannel.appendLine("");
      combinedStderr += `${attempt.label} stderr:\n${result.stderr}\n`;
    }

    if (result.error) {
      lastError = result.error;

      outputChannel.appendLine(`Attempt failed: ${result.error.message}`);
      outputChannel.appendLine("");

      if (isCommandNotFoundError(result.error)) {
        continue;
      }

      vscode.window.showErrorMessage(`SecurePy failed: ${result.error.message}`);
      return;
    }

    const stdout = result.stdout ?? "";

    if (!stdout.trim()) {
      diagnosticCollection.clear();
      outputChannel.appendLine("No JSON output received from SecurePy.");
      vscode.window.showWarningMessage("SecurePy completed, but returned no JSON output.");
      return;
    }

    outputChannel.appendLine("stdout:");
    outputChannel.appendLine(stdout);
    outputChannel.appendLine("");

    try {
      const parsed = JSON.parse(stdout) as SecurePyJson;
      await applyDiagnostics(parsed);
      if (showOutput) {
        vscode.window.showInformationMessage("SecurePy scan complete.");
      }
      return;
    } catch (parseError) {
      outputChannel.appendLine("Failed to parse SecurePy JSON output.");
      outputChannel.appendLine(String(parseError));
      vscode.window.showWarningMessage("SecurePy completed, but JSON parsing failed.");
      return;
    }
  }

  const installMessage =
    "SecurePy could not be launched. Install it with 'pip install securepy' or set 'securepy.executablePath' in VS Code settings.";

  if (combinedStderr.trim()) {
    outputChannel.appendLine("All launch attempts failed.");
    outputChannel.appendLine(combinedStderr);
  }

  vscode.window.showErrorMessage(installMessage);
}

function execFileAsync(
  command: string,
  args: string[],
  cwd?: string
): Promise<{ stdout: string; stderr: string; error: Error | null }> {
  return new Promise((resolve) => {
    execFile(command, args, { cwd }, (error, stdout, stderr) => {
      resolve({
        stdout: stdout ?? "",
        stderr: stderr ?? "",
        error: error ?? null
      });
    });
  });
}

function isCommandNotFoundError(error: Error): boolean {
  const maybeNodeError = error as NodeJS.ErrnoException;
  return maybeNodeError.code === "ENOENT";
}

async function applyDiagnostics(data: SecurePyJson): Promise<void> {
  diagnosticCollection.clear();

  const issues = data.findings ?? data.issues ?? data.results ?? [];
  const diagnosticsByFile = new Map<string, vscode.Diagnostic[]>();

  for (const issue of issues) {
    const filePath = issue.file_path ?? issue.filename ?? issue.file ?? issue.path;
    if (!filePath) {
      continue;
    }

    const line = Math.max((issue.line ?? issue.line_number ?? 1) - 1, 0);
    const rawCol = issue.column ?? issue.col ?? 1;
    const col = Math.max((rawCol ?? 1) - 1, 0);

    const messageParts: string[] = [];

    if (issue.title) {
      messageParts.push(issue.title);
    }

    if (issue.message) {
      messageParts.push(issue.message);
    }

    if (issue.remediation) {
      messageParts.push(`Remediation: ${issue.remediation}`);
    }

    const message = messageParts.join(" ") || "SecurePy reported an issue.";
    const code = issue.test_id ?? issue.rule_id ?? "securepy";
    const severity = mapSeverity(issue.severity);

    const uri = vscode.Uri.file(filePath);
    const range = await buildDiagnosticRange(uri, line, col, issue.column ?? issue.col ?? null);

    const diagnostic = new vscode.Diagnostic(
      range,
      `${message} [${code}]`,
      severity
    );

    diagnostic.source = "SecurePy";
    diagnostic.code = code;

    const existing = diagnosticsByFile.get(filePath) ?? [];
    existing.push(diagnostic);
    diagnosticsByFile.set(filePath, existing);
  }

  for (const [filePath, diagnostics] of diagnosticsByFile.entries()) {
    diagnosticCollection.set(vscode.Uri.file(filePath), diagnostics);
  }

  outputChannel.appendLine(`Applied ${issues.length} diagnostic(s).`);
}

async function buildDiagnosticRange(
  uri: vscode.Uri,
  line: number,
  col: number,
  rawColumn: number | null
): Promise<vscode.Range> {
  try {
    const document = await vscode.workspace.openTextDocument(uri);

    const safeLine = Math.min(line, Math.max(document.lineCount - 1, 0));
    const lineText = document.lineAt(safeLine).text;

    if (rawColumn === null || rawColumn === undefined) {
      return new vscode.Range(
        new vscode.Position(safeLine, 0),
        new vscode.Position(safeLine, Math.max(lineText.length, 1))
      );
    }

    const safeCol = Math.min(col, Math.max(lineText.length, 0));

    const tokenMatch = lineText.slice(safeCol).match(/^[A-Za-z_][A-Za-z0-9_.=()'", ]*/);
    const tokenLength = tokenMatch ? tokenMatch[0].length : 1;
    const endCol = Math.min(safeCol + Math.max(tokenLength, 1), Math.max(lineText.length, 1));

    return new vscode.Range(
      new vscode.Position(safeLine, safeCol),
      new vscode.Position(safeLine, endCol)
    );
  } catch {
    return new vscode.Range(
      new vscode.Position(line, col),
      new vscode.Position(line, col + 1)
    );
  }
}

function mapSeverity(severity?: string): vscode.DiagnosticSeverity {
  switch ((severity ?? "").toLowerCase()) {
    case "high":
    case "error":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
    case "warning":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
    case "info":
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Warning;
  }
}

function isPythonDocument(document: vscode.TextDocument): boolean {
  return document.languageId === "python" || document.fileName.endsWith(".py");
}

function getScanCwdForDocument(document: vscode.TextDocument): string | undefined {
  const workspaceFolder = vscode.workspace.getWorkspaceFolder(document.uri);
  return workspaceFolder?.uri.fsPath;
}