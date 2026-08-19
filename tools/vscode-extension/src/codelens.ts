import * as vscode from "vscode";
import { ConstellationClient } from "./client";

const IMAGE_LINE_RE = /^\s*(?:image|FROM)\s*[:=]?\s*(["']?)([^\s"'#]+)\1/i;

/**
 * Code-lens that shows the most recent scan summary for any `image:` ref
 * found in YAML/Dockerfiles.
 */
export class ImageCodeLensProvider implements vscode.CodeLensProvider {
  private _emitter = new vscode.EventEmitter<void>();
  readonly onDidChangeCodeLenses = this._emitter.event;

  constructor(private client: ConstellationClient) {}

  refresh(): void {
    this._emitter.fire();
  }

  async provideCodeLenses(doc: vscode.TextDocument): Promise<vscode.CodeLens[]> {
    const lenses: vscode.CodeLens[] = [];
    for (let i = 0; i < doc.lineCount; i++) {
      const line = doc.lineAt(i).text;
      const m = line.match(IMAGE_LINE_RE);
      if (!m) continue;
      const ref = m[2];
      if (!ref || !ref.includes(":") || ref.startsWith("$")) continue;

      const range = new vscode.Range(i, 0, i, line.length);
      const findings = await this.client.findingsForImage(ref);
      const counts = bySeverity(findings);

      let title = `Constellation: no findings for ${ref}`;
      if (findings.length > 0) {
        const parts: string[] = [];
        if (counts.critical) parts.push(`${counts.critical} critical`);
        if (counts.high)     parts.push(`${counts.high} high`);
        if (counts.medium)   parts.push(`${counts.medium} medium`);
        if (counts.low)      parts.push(`${counts.low} low`);
        title = `Constellation: ${parts.join(", ")} (${ref})`;
      }

      lenses.push(new vscode.CodeLens(range, {
        title,
        command: "constellation.refreshFindings",
        tooltip: "Click to refresh findings",
      }));
    }
    return lenses;
  }
}

function bySeverity(findings: { severity: string }[]): Record<string, number> {
  const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  return counts;
}
