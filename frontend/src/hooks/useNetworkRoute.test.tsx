import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { createMemoryHistory, type RouterHistory } from "@tanstack/react-router";
import { afterEach, expect, it, vi } from "vitest";
import { TestRouter } from "@/test/router";
import { useNetworkRoute } from "./useNetworkRoute";

let current: ReturnType<typeof useNetworkRoute>;
let root: Root; let host: HTMLDivElement; let history: RouterHistory;
function Workspace() { current = useNetworkRoute(); return <p>{current.workspaceTab}:{current.hours}:{current.conversationPage}</p>; }
async function render(url: string) {
  host = document.createElement("div"); document.body.append(host); root = createRoot(host);
  history = createMemoryHistory({ initialEntries: [url] });
  await act(async () => root.render(<TestRouter history={history}><Workspace /></TestRouter>));
  await vi.waitFor(() => expect(host.textContent).not.toBe(""));
}
afterEach(() => { act(() => root?.unmount()); host?.remove(); });

it("keeps exact directed endpoints and server page through tabs and Back/Forward", async () => {
  await render("/clusters/c/network?tab=conversations&from=prod%2Fapi&to=other%2Fapi&verdict_group=blocked&conversation_page=3&hide_platform=false&context=dashboard#evidence");
  expect(current.conversationPage).toBe(2);
  await act(async () => current.setWorkspaceTab("sessions"));
  expect(current.params.get("from")).toBe("prod/api"); expect(history.location.hash).toBe("#evidence");
  await act(async () => history.back());
  await vi.waitFor(() => expect(current.workspaceTab).toBe("conversations"));
  expect(current.conversationPage).toBe(2); expect(current.params.get("to")).toBe("other/api");
  await act(async () => history.forward());
  await vi.waitFor(() => expect(current.workspaceTab).toBe("sessions"));
});
it("resets pagination on a changed filter and restores it on Back", async () => {
  await render("/network?tab=conversations&conversation_page=4&from=prod%2Fapi&context=dashboard");
  await act(async () => current.setHours(168));
  expect(current.hours).toBe(168); expect(current.conversationPage).toBe(0);
  expect(current.params.get("from")).toBe("prod/api"); expect(current.params.get("context")).toBe("dashboard");
  await act(async () => history.back());
  await vi.waitFor(() => expect(current.conversationPage).toBe(3)); expect(current.hours).toBe(24);
});
it("applies a saved view atomically without discarding unrelated URL context", async () => {
  await render("/network?tab=conversations&conversation_page=4&flow=old&from=old&context=dashboard#notes");
  await act(async () => current.update({tab:"rules",hours:"168",from:null,to:null,flow:null,hide_platform:"false"},false,true));
  expect(current.workspaceTab).toBe("rules"); expect(current.conversationPage).toBe(0); expect(current.params.has("from")).toBe(false);
  expect(current.params.get("context")).toBe("dashboard"); expect(history.location.hash).toBe("#notes");
  await act(async () => history.back());
  await vi.waitFor(() => expect(current.conversationPage).toBe(3)); expect(current.selectedFlowID).toBe("old");
});
it("clamps invalid windows/pages and retains literal endpoint filters", async () => {
  await render("/network?hours=-1&conversation_page=Infinity&from=ns%2F%25_api&to=external&tab=unknown");
  expect(current.hours).toBe(24); expect(current.conversationPage).toBe(0); expect(current.workspaceTab).toBe("map");
  expect(current.params.get("from")).toBe("ns/%_api");
});
