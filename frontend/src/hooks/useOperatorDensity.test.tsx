import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, expect, it } from "vitest";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { operatorStorageKey } from "@/lib/operator-preferences";
import { useOperatorDensity } from "./useOperatorDensity";
let root: Root; let host: HTMLDivElement;
afterEach(() => { act(() => root?.unmount()); host?.remove(); localStorage.clear(); });
function Harness() {
  const [density, setDensity] = useOperatorDensity("findings.density");
  return <button onClick={() => setDensity("compact")}>{density}</button>;
}
function render(org = "org", user = "user") {
  if (!host) { host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host); }
  act(() => root.render(<TablePreferencesProvider identity={{ org_id: org, user_id: user }}><Harness /></TablePreferencesProvider>));
}
it("restores only the active operator's density and normalizes invalid stored values", () => {
  localStorage.setItem("findings.density", "comfy");
  render(); expect(host.textContent).toBe("cozy");
  act(() => host.querySelector("button")!.click()); expect(host.textContent).toBe("compact");
  render("other"); expect(host.textContent).toBe("cozy");
  render("org", "other"); expect(host.textContent).toBe("cozy");
  render(); expect(host.textContent).toBe("compact");
  const key = operatorStorageKey("findings.density", { org_id: "invalid", user_id: "user" })!;
  localStorage.setItem(key, "broken"); render("invalid"); expect(host.textContent).toBe("cozy");
  expect(localStorage.getItem(operatorStorageKey("findings.density", { org_id: "org", user_id: "user" })!)).toBe("compact");
});
