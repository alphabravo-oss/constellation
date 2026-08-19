// Constellation VS Code extension — entry point.
//
// Features:
//   - Findings tree view in the Explorer sidebar.
//   - Code lens above `image: <ref>` in YAML / Dockerfiles showing the most
//     recent scan result.
//   - Hover provider that explains the CVE pinned to a finding.
//   - "Upgrade to <fixed-version>" quick-fix code action.
//   - Inline diagnostics (carries over from v0.1).
//   - Device-code style sign-in via /api/v1/auth/cli-init.
//
// The extension talks to a Constellation API server configured via
// `constellation.serverUrl` + `constellation.token`. All HTTP uses the
// built-in `fetch` (Node 18+ / VS Code 1.92+).
import * as vscode from "vscode";
import { ConstellationClient, Finding } from "./client";
import { FindingsProvider } from "./findingsView";
import { ImageCodeLensProvider } from "./codelens";
import { FindingHoverProvider } from "./hover";
import { UpgradeFixedVersionAction } from "./codeAction";
import { signInDeviceCode } from "./auth";

const COLLECTION_NAME = "constellation";

export function activate(ctx: vscode.ExtensionContext): void {
  const diags = vscode.languages.createDiagnosticCollection(COLLECTION_NAME);
  ctx.subscriptions.push(diags);

  const client = new ConstellationClient(() => readConfig());

  // --- Sidebar tree view -------------------------------------------------
  const findingsProvider = new FindingsProvider(client);
  const treeView = vscode.window.createTreeView("constellationFindings", {
    treeDataProvider: findingsProvider,
    showCollapseAll: true,
  });
  ctx.subscriptions.push(treeView);

  // --- Code lens above image: refs --------------------------------------
  const lensSelector: vscode.DocumentSelector = [
    { language: "yaml" },
    { language: "dockerfile" },
  ];
  const lensProvider = new ImageCodeLensProvider(client);
  ctx.subscriptions.push(
    vscode.languages.registerCodeLensProvider(lensSelector, lensProvider),
  );

  // --- Hover provider ---------------------------------------------------
  const hoverProvider = new FindingHoverProvider(client);
  ctx.subscriptions.push(
    vscode.languages.registerHoverProvider(
      [...lensSelector, { language: "terraform" }],
      hoverProvider,
    ),
  );

  // --- Quick-fix code actions ------------------------------------------
  const codeActionProvider = new UpgradeFixedVersionAction(client);
  ctx.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      lensSelector,
      codeActionProvider,
      { providedCodeActionKinds: UpgradeFixedVersionAction.providedKinds },
    ),
  );

  // --- Commands ---------------------------------------------------------
  ctx.subscriptions.push(
    vscode.commands.registerCommand("constellation.scanCurrentFile", async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showWarningMessage("Constellation: no active editor.");
        return;
      }
      try {
        const findings = await client.listFindings();
        diags.set(editor.document.uri, findings.map(toDiagnostic));
        vscode.window.showInformationMessage(
          `Constellation: ${findings.length} findings shown inline.`,
        );
      } catch (err) {
        vscode.window.showErrorMessage(`Constellation: ${(err as Error).message}`);
      }
    }),

    vscode.commands.registerCommand("constellation.openFinding", async (id?: string) => {
      const value = id ?? (await vscode.window.showInputBox({ prompt: "Finding ID" }));
      if (!value) return;
      const cfg = readConfig();
      const url = `${cfg.serverUrl.replace(/\/$/, "")}/findings/${value}`;
      vscode.env.openExternal(vscode.Uri.parse(url));
    }),

    vscode.commands.registerCommand("constellation.refreshFindings", () => {
      findingsProvider.refresh();
      lensProvider.refresh();
    }),

    vscode.commands.registerCommand("constellation.signIn", async () => {
      try {
        const token = await signInDeviceCode(client);
        if (token) {
          await vscode.workspace
            .getConfiguration("constellation")
            .update("token", token, vscode.ConfigurationTarget.Global);
          vscode.window.showInformationMessage("Constellation: signed in.");
          findingsProvider.refresh();
        }
      } catch (err) {
        vscode.window.showErrorMessage(`Constellation sign-in: ${(err as Error).message}`);
      }
    }),

    vscode.commands.registerCommand(
      "constellation.upgradeToFixed",
      async (uri: vscode.Uri, range: vscode.Range, replacement: string) => {
        const editor = await vscode.window.showTextDocument(uri);
        await editor.edit((b) => b.replace(range, replacement));
      },
    ),
  );

  // Initial load.
  findingsProvider.refresh();
}

export function deactivate(): void {
  /* noop */
}

interface Config {
  serverUrl: string;
  token: string;
  repoScope: string;
}

function readConfig(): Config {
  const cfg = vscode.workspace.getConfiguration("constellation");
  return {
    serverUrl: cfg.get<string>("serverUrl") ?? "http://localhost:8080",
    token:     cfg.get<string>("token") ?? "",
    repoScope: cfg.get<string>("repoScope") ?? "",
  };
}

function toDiagnostic(f: Finding): vscode.Diagnostic {
  const range = new vscode.Range(0, 0, 0, 0);
  const d = new vscode.Diagnostic(
    range,
    `${f.external_id ?? ""} ${f.title} (risk ${f.risk_score})`,
    severityToVS(f.severity),
  );
  d.source = COLLECTION_NAME;
  d.code = { value: f.id, target: vscode.Uri.parse("command:constellation.openFinding") };
  return d;
}

function severityToVS(sev: Finding["severity"]): vscode.DiagnosticSeverity {
  switch (sev) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
      return vscode.DiagnosticSeverity.Information;
  }
  return vscode.DiagnosticSeverity.Hint;
}
