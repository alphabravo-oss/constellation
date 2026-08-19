import * as vscode from "vscode";
import { ConstellationClient, Finding } from "./client";

const IMAGE_LINE_RE = /^\s*(?:image|FROM)\s*[:=]?\s*(["']?)([^\s"'#]+)\1/i;

/**
 * Hover provider that shows the top CVEs for an image ref on the line
 * the cursor is hovering over.
 */
export class FindingHoverProvider implements vscode.HoverProvider {
  constructor(private client: ConstellationClient) {}

  async provideHover(doc: vscode.TextDocument, pos: vscode.Position): Promise<vscode.Hover | undefined> {
    const line = doc.lineAt(pos.line).text;
    const m = line.match(IMAGE_LINE_RE);
    if (!m) return undefined;
    const ref = m[2];
    if (!ref || !ref.includes(":")) return undefined;

    const findings = await this.client.findingsForImage(ref);
    if (findings.length === 0) {
      return new vscode.Hover(new vscode.MarkdownString(
        `**Constellation** — no findings for \`${ref}\`.`,
      ));
    }
    return new vscode.Hover(buildMarkdown(ref, findings));
  }
}

function buildMarkdown(ref: string, findings: Finding[]): vscode.MarkdownString {
  const md = new vscode.MarkdownString();
  md.isTrusted = true;
  md.supportThemeIcons = true;
  md.appendMarkdown(`### Constellation — \`${ref}\`\n\n`);
  md.appendMarkdown(`| Severity | CVE | Package | Fixed in |\n`);
  md.appendMarkdown(`|---|---|---|---|\n`);
  for (const f of findings.slice(0, 10)) {
    const pkg = f.package ? `${f.package.name}@${f.package.version}` : "—";
    const fix = f.fixed_version ?? "—";
    md.appendMarkdown(
      `| ${f.severity} | ${f.external_id ?? f.id} | ${pkg} | ${fix} |\n`,
    );
  }
  if (findings.length > 10) {
    md.appendMarkdown(`\n_…and ${findings.length - 10} more_\n`);
  }
  return md;
}
