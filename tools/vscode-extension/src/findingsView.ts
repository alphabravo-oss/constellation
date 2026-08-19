import * as vscode from "vscode";
import { ConstellationClient, Finding } from "./client";

/**
 * Tree provider for the "Constellation Findings" view. Groups findings by
 * severity, expandable into individual finding nodes.
 */
export class FindingsProvider implements vscode.TreeDataProvider<TreeNode> {
  private _emitter = new vscode.EventEmitter<TreeNode | undefined | void>();
  readonly onDidChangeTreeData = this._emitter.event;

  private findings: Finding[] = [];
  private loaded = false;

  constructor(private client: ConstellationClient) {}

  refresh(): void {
    this.loaded = false;
    this._emitter.fire();
  }

  async getChildren(element?: TreeNode): Promise<TreeNode[]> {
    if (!this.loaded) {
      try {
        this.findings = await this.client.listFindings({ limit: 200 });
      } catch (err) {
        return [
          new MessageNode(`Error: ${(err as Error).message}`),
          new MessageNode("Set constellation.token and run 'Refresh'."),
        ];
      }
      this.loaded = true;
    }

    if (!element) {
      const order: Finding["severity"][] = ["critical", "high", "medium", "low", "info"];
      return order
        .map((sev) => ({ sev, items: this.findings.filter((f) => f.severity === sev) }))
        .filter((g) => g.items.length > 0)
        .map((g) => new GroupNode(g.sev, g.items));
    }

    if (element instanceof GroupNode) {
      return element.items.map((f) => new FindingNode(f));
    }
    return [];
  }

  getTreeItem(node: TreeNode): vscode.TreeItem {
    return node;
  }
}

type TreeNode = GroupNode | FindingNode | MessageNode;

class GroupNode extends vscode.TreeItem {
  constructor(public severity: Finding["severity"], public items: Finding[]) {
    super(`${severity.toUpperCase()} (${items.length})`, vscode.TreeItemCollapsibleState.Expanded);
    this.iconPath = new vscode.ThemeIcon(iconForSeverity(severity));
    this.contextValue = "constellation.group";
  }
}

class FindingNode extends vscode.TreeItem {
  constructor(public finding: Finding) {
    super(label(finding), vscode.TreeItemCollapsibleState.None);
    this.description = finding.external_id;
    this.tooltip = finding.description ?? finding.title;
    this.iconPath = new vscode.ThemeIcon(iconForSeverity(finding.severity));
    this.command = {
      command: "constellation.openFinding",
      title: "Open finding",
      arguments: [finding.id],
    };
    this.contextValue = "constellation.finding";
  }
}

class MessageNode extends vscode.TreeItem {
  constructor(text: string) {
    super(text, vscode.TreeItemCollapsibleState.None);
    this.iconPath = new vscode.ThemeIcon("info");
  }
}

function label(f: Finding): string {
  if (f.package?.name) {
    return `${f.title} — ${f.package.name}@${f.package.version}`;
  }
  return f.title;
}

function iconForSeverity(s: Finding["severity"]): string {
  switch (s) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
      return "info";
  }
  return "circle-outline";
}
