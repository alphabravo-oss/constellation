import * as vscode from "vscode";
import { ConstellationClient } from "./client";

/**
 * Device-code sign-in flow. Shows the verification URL + code to the
 * developer, polls the server until the user confirms, and returns the
 * issued token.
 *
 * Falls back to a plain InputBox if the server doesn't expose
 * `/api/v1/auth/cli-init`.
 */
export async function signInDeviceCode(client: ConstellationClient): Promise<string | undefined> {
  let init;
  try {
    init = await client.startCliInit();
  } catch (err) {
    const msg = (err as Error).message;
    if (!msg.includes("cli-init: 404") && !msg.includes("cli-init: 501")) {
      throw err;
    }
    // Fallback path: server hasn't enabled device-code auth yet.
    const token = await vscode.window.showInputBox({
      prompt: "Paste a constellationctl token (server has no device-code endpoint).",
      password: true,
      ignoreFocusOut: true,
    });
    return token ?? undefined;
  }

  await vscode.env.clipboard.writeText(init.user_code);
  const opened = await vscode.window.showInformationMessage(
    `Constellation: open ${init.verification_uri} and enter code ${init.user_code} (copied to clipboard).`,
    "Open browser",
    "Cancel",
  );
  if (opened === "Cancel") return undefined;
  if (opened === "Open browser") {
    await vscode.env.openExternal(vscode.Uri.parse(init.verification_uri));
  }

  const deadline = Date.now() + Math.max(60, init.expires_in) * 1000;
  const interval = Math.max(2, init.interval) * 1000;

  return await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: "Constellation: waiting for sign-in…", cancellable: true },
    async (_progress, cancellation) => {
      while (Date.now() < deadline) {
        if (cancellation.isCancellationRequested) return undefined;
        await new Promise((r) => setTimeout(r, interval));
        try {
          const r = await client.pollCliInit(init.device_code);
          if (r.token) return r.token;
        } catch (err) {
          throw err;
        }
      }
      throw new Error("device code expired");
    },
  );
}
