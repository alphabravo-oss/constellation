import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";
import { VerdictBanner } from "./verdict-banner";

let root: Root;
let host: HTMLDivElement;
Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
afterEach(() => { act(() => root?.unmount()); host?.remove(); });
function render(props: Parameters<typeof VerdictBanner>[0]) {
  host = document.createElement("div"); document.body.append(host);
  root = createRoot(host); act(() => root.render(<VerdictBanner {...props} />));
}
it("keeps status and actions visible while disclosing supporting context on demand", () => {
  const retry = vi.fn();
  render({ status: "degraded", title: "Host findings need review", detail: "Counts cover matching nodes.", actions: <button onClick={retry}>Retry</button> });
  const toggle = host.querySelector<HTMLButtonElement>("button[aria-expanded]")!;
  const detail = document.getElementById(toggle.getAttribute("aria-controls")!)!;
  expect(host.textContent).toContain("Host findings need review");
  expect(toggle.getAttribute("aria-expanded")).toBe("false"); expect(detail.hidden).toBe(true);
  // The action remains independently operable when supporting detail is closed.
  act(() => [...host.querySelectorAll("button")].find(button => button.textContent === "Retry")?.click());
  expect(retry).toHaveBeenCalled();
  act(() => toggle.click()); expect(detail.hidden).toBe(false); expect(toggle.getAttribute("aria-expanded")).toBe("true");
  act(() => toggle.click()); expect(detail.hidden).toBe(true);
});
it("keeps essential action consequences inline without an extra control", () => {
  render({ status: "info", title: "Quarantine workload", detail: "New pods will be blocked.", detailMode: "inline" });
  expect(host.querySelector("button[aria-expanded]")).toBeNull();
  expect(host.querySelector<HTMLElement>("[id]")!.hidden).toBe(false);
});
it("does not render an empty disclosure", () => {
  render({ status: "ok", title: "Connected" });
  expect(host.querySelector("button")).toBeNull();
});
