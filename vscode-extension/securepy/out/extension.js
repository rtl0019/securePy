"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = __importStar(require("vscode"));
const child_process_1 = require("child_process");
let outputChannel;
let diagnosticCollection;
function activate(context) {
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
    const scanOnSaveDisposable = vscode.workspace.onDidSaveTextDocument(async (document) => {
        const config = vscode.workspace.getConfiguration();
        const scanOnSave = config.get("securepy.scanOnSave", false);
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
    context.subscriptions.push(scanFileCommand, scanWorkspaceCommand, clearDiagnosticsCommand, scanOnSaveDisposable, outputChannel, diagnosticCollection);
}
function deactivate() { }
async function runSecurePyScan(targets, cwd, showOutput = true) {
    const config = vscode.workspace.getConfiguration();
    const executablePath = config.get("securepy.executablePath", "securepy");
    const extraArgs = config.get("securepy.scanArgs", [
        "--format",
        "json",
        "--stdout",
        "--no-color"
    ]);
    const args = ["scan", ...targets, ...extraArgs];
    outputChannel.clear();
    if (showOutput) {
        outputChannel.show(true);
    }
    outputChannel.appendLine(`Running: ${executablePath} ${args.join(" ")}`);
    outputChannel.appendLine("");
    (0, child_process_1.execFile)(executablePath, args, { cwd }, async (error, stdout, stderr) => {
        if (stderr) {
            outputChannel.appendLine("stderr:");
            outputChannel.appendLine(stderr);
            outputChannel.appendLine("");
        }
        if (error) {
            vscode.window.showErrorMessage(`SecurePy failed: ${error.message}`);
            return;
        }
        if (!stdout || !stdout.trim()) {
            diagnosticCollection.clear();
            outputChannel.appendLine("No JSON output received from SecurePy.");
            vscode.window.showWarningMessage("SecurePy completed, but returned no JSON output.");
            return;
        }
        outputChannel.appendLine("stdout:");
        outputChannel.appendLine(stdout);
        outputChannel.appendLine("");
        try {
            const parsed = JSON.parse(stdout);
            await applyDiagnostics(parsed);
            if (showOutput) {
                vscode.window.showInformationMessage("SecurePy scan complete.");
            }
        }
        catch (parseError) {
            outputChannel.appendLine("Failed to parse SecurePy JSON output.");
            outputChannel.appendLine(String(parseError));
            vscode.window.showWarningMessage("SecurePy completed, but JSON parsing failed.");
        }
    });
}
async function applyDiagnostics(data) {
    diagnosticCollection.clear();
    const issues = data.findings ?? data.issues ?? data.results ?? [];
    const diagnosticsByFile = new Map();
    for (const issue of issues) {
        const filePath = issue.file_path ?? issue.filename ?? issue.file ?? issue.path;
        if (!filePath) {
            continue;
        }
        const line = Math.max((issue.line ?? issue.line_number ?? 1) - 1, 0);
        const rawCol = issue.column ?? issue.col ?? 1;
        const col = Math.max((rawCol ?? 1) - 1, 0);
        const messageParts = [];
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
        const diagnostic = new vscode.Diagnostic(range, `${message} [${code}]`, severity);
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
async function buildDiagnosticRange(uri, line, col, rawColumn) {
    try {
        const document = await vscode.workspace.openTextDocument(uri);
        const safeLine = Math.min(line, Math.max(document.lineCount - 1, 0));
        const lineText = document.lineAt(safeLine).text;
        if (rawColumn === null || rawColumn === undefined) {
            return new vscode.Range(new vscode.Position(safeLine, 0), new vscode.Position(safeLine, Math.max(lineText.length, 1)));
        }
        const safeCol = Math.min(col, Math.max(lineText.length, 0));
        const endCol = Math.min(safeCol + 1, Math.max(lineText.length, 1));
        return new vscode.Range(new vscode.Position(safeLine, safeCol), new vscode.Position(safeLine, endCol));
    }
    catch {
        return new vscode.Range(new vscode.Position(line, col), new vscode.Position(line, col + 1));
    }
}
function mapSeverity(severity) {
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
function isPythonDocument(document) {
    return document.languageId === "python" || document.fileName.endsWith(".py");
}
function getScanCwdForDocument(document) {
    const workspaceFolder = vscode.workspace.getWorkspaceFolder(document.uri);
    return workspaceFolder?.uri.fsPath;
}
//# sourceMappingURL=extension.js.map