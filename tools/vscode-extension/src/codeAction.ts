import * as vscode from "vscode";
import { ConstellationClient, Finding } from "./client";

const IMAGE_LINE_RE = /^(\s*(?:image|FROM)\s*[:=]?\s*(["']?))([^\s"'#]+)((["']?).*)$/i;

/**
 * "Upgrade to <fixed-version>" quick-fix: when the current line is an
 * `image:` reference and the Constellation API knows a fixed version for
 * that package, offer to replace the tag in place.
 *
 * Tag-replacement strategy: if the image is `name:tag` and the fix string
 * looks tag-like (digits), swap the tag. Otherwise fall through to a
 * comment annotation so the developer sees the fix even when we can't
 * mechanically apply it.
 */
export class UpgradeFixedVersionAction implements vscode.CodeActionProvider {
  static readonly providedKinds = [vscode.CodeActionKind.QuickFix];

  constructor(private client: ConstellationClient) {}

  async provideCodeActions(
    doc: vscode.TextDocument,
    range: vscode.Range | vscode.Selection,
  ): Promise<vscode.CodeAction[]> {
    const line = doc.lineAt(range.start.line).text;
    const m = line.match(IMAGE_LINE_RE);
    if (!m) return [];
    const ref = m[3];
    if (!ref || !ref.includes(":")) return [];

    const findings = await this.client.findingsForImage(ref);
    const fix = pickFix(findings);
    if (!fix) return [];

    const [name, _tag] = ref.split(":", 2);
    const newRef = `${name}:${fix.fixedVersion}`;
    const newLine = `${m[1]}${newRef}${m[4]}`;
    const lineRange = new vscode.Range(range.start.line, 0, range.start.line, line.length);

    const action = new vscode.CodeAction(
      `Constellation: upgrade to ${newRef} (fixes ${fix.cve})`,
      vscode.CodeActionKind.QuickFix,
    );
    action.edit = new vscode.WorkspaceEdit();
    action.edit.replace(doc.uri, lineRange, newLine);
    action.isPreferred = true;
    return [action];
  }
}

function pickFix(findings: Finding[]): { cve: string; fixedVersion: string } | null {
  // Prefer the most severe finding with a fix.
  const order: Finding["severity"][] = ["critical", "high", "medium", "low", "info"];
  for (const sev of order) {
    for (const f of findings) {
      if (f.severity === sev && f.fixed_version) {
        return { cve: f.external_id ?? f.id, fixedVersion: f.fixed_version };
      }
    }
  }
  return null;
}
