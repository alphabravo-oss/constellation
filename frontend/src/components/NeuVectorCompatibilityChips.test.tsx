import { act, type ReactNode } from "react";
import { MemoryRouter } from "react-router-dom";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it } from "vitest";

import { NeuVectorCompatibilityChips } from "./NeuVectorCompatibilityChips";

let root: Root | undefined;
let host: HTMLDivElement | undefined;

afterEach(() => {
  if (root) {
    act(() => root?.unmount());
  }
  host?.remove();
  root = undefined;
  host = undefined;
  document.body.innerHTML = "";
});

describe("NeuVectorCompatibilityChips", () => {
  it("renders NeuVector mapping labels and linked actions", () => {
    render(
      <NeuVectorCompatibilityChips
        items={[
          { label: "NV DLP Sensors -> DLP Rules" },
          { label: "NV dlp_group -> DLP group scope" },
          { label: "Migration Imports", to: "/settings/migration" },
        ]}
      />,
    );

    expect(host?.textContent).toContain("NV DLP Sensors -> DLP Rules");
    expect(host?.textContent).toContain("NV dlp_group -> DLP group scope");
    expect(host?.querySelector<HTMLAnchorElement>("a[href='/settings/migration']")?.textContent).toBe("Migration Imports");
  });
});

function render(ui: ReactNode) {
  if (root) {
    act(() => root?.unmount());
  }
  host?.remove();
  host = document.createElement("div");
  document.body.appendChild(host);
  root = createRoot(host);
  act(() => {
    root?.render(<MemoryRouter>{ui}</MemoryRouter>);
  });
}
