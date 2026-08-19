// HTTP client for the Constellation API.
export interface Finding {
  id: string;
  title: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  risk_score: number;
  external_id?: string;
  description?: string;
  fixed_version?: string;
  package?: { name: string; version: string };
  target?: { repo?: string; image?: string };
}

export interface ConfigGetter {
  (): { serverUrl: string; token: string; repoScope: string };
}

export class ConstellationClient {
  constructor(private cfg: ConfigGetter) {}

  private base(): string {
    return this.cfg().serverUrl.replace(/\/$/, "");
  }

  private headers(): Record<string, string> {
    const h: Record<string, string> = { Accept: "application/json" };
    const t = this.cfg().token;
    if (t) h.Authorization = `Bearer ${t}`;
    return h;
  }

  async listFindings(opts: { limit?: number; image?: string } = {}): Promise<Finding[]> {
    const q = new URLSearchParams();
    q.set("limit", String(opts.limit ?? 50));
    q.set("lifecycle", "open");
    const repo = this.cfg().repoScope;
    if (repo) q.set("repo", repo);
    if (opts.image) q.set("image", opts.image);

    const url = `${this.base()}/api/v1/findings?${q.toString()}`;
    const res = await fetch(url, { headers: this.headers() });
    if (!res.ok) throw new Error(`API ${res.status}: ${await res.text()}`);
    const body = (await res.json()) as { findings?: Finding[] };
    return body.findings ?? [];
  }

  /**
   * Fetch the most recent findings for an image ref. Used by the code lens.
   */
  async findingsForImage(ref: string): Promise<Finding[]> {
    try {
      return await this.listFindings({ image: ref, limit: 25 });
    } catch {
      return [];
    }
  }

  // -------------------- device-code auth --------------------
  async startCliInit(): Promise<{ device_code: string; user_code: string; verification_uri: string; expires_in: number; interval: number }>
  {
    const res = await fetch(`${this.base()}/api/v1/auth/cli-init`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ client: "vscode-extension" }),
    });
    if (!res.ok) throw new Error(`cli-init: ${res.status}`);
    return res.json() as Promise<any>;
  }

  async pollCliInit(deviceCode: string): Promise<{ token?: string; pending?: boolean }>
  {
    const res = await fetch(`${this.base()}/api/v1/auth/cli-poll`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ device_code: deviceCode }),
    });
    if (res.status === 202) return { pending: true };
    if (!res.ok) throw new Error(`cli-poll: ${res.status}`);
    const body = (await res.json()) as { token?: string };
    return { token: body.token };
  }
}
