import { act, useState } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it } from "vitest";
import { Pager } from "./pager";

let root: Root;
let host: HTMLDivElement;

beforeEach(() => {
  (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  host = document.createElement("div");
  document.body.append(host);
  root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); });
const button = (label: string) => [...host.querySelectorAll<HTMLButtonElement>("button")].find((item) => item.textContent === label || item.getAttribute("aria-label") === label)!;
async function click(label: string) { await act(async () => button(label).click()); }

function TotalPages({ initialPage = 0, total = 250 }: { initialPage?: number; total?: number }) {
  const [page, setPage] = useState(initialPage);
  const rows = Math.min(100, Math.max(0, total - page * 100));
  return <Pager page={page} pageSize={100} total={total} rowsOnPage={rows} onPage={setPage} />;
}

it("shows an empty out-of-range page as 0–0 and allows recovery without an invented range", async () => {
  await act(async () => root.render(<TotalPages initialPage={2} total={58} />));
  expect(host.textContent).toContain("Showing 0–0 of 58");
  expect(host.textContent).toContain("Page 3 of 1");
  expect(button("Next").disabled).toBe(true);
  expect(button("Prev").disabled).toBe(false);
  await click("Prev");
  expect(host.textContent).toContain("Showing 0–0 of 58");
  await click("Prev");
  expect(host.querySelector("button")).toBeNull();
});

it("preserves exact ranges and navigation across first, middle and partial final total pages", async () => {
  await act(async () => root.render(<TotalPages />));
  expect(host.textContent).toContain("Showing 1–100 of 250");
  expect(button("Prev").disabled).toBe(true);
  expect(button("Next").disabled).toBe(false);
  await click("Next");
  expect(host.textContent).toContain("Showing 101–200 of 250");
  expect(host.textContent).toContain("Page 2 of 3");
  await click("Next");
  expect(host.textContent).toContain("Showing 201–250 of 250");
  expect(button("Next").disabled).toBe(true);
  await click("Prev");
  expect(host.textContent).toContain("Showing 101–200 of 250");
});

function CursorPages() {
  const [page, setPage] = useState(0);
  return <Pager page={page} pageSize={100} rowsOnPage={page === 0 ? 100 : page === 1 ? 20 : 0} hasMore={page < 1} onPage={setPage} />;
}

it("uses cursor availability for navigation without inventing a total or page count", async () => {
  await act(async () => root.render(<CursorPages />));
  expect(host.textContent).toContain("Showing 1–100");
  expect(host.textContent).not.toContain(" of ");
  expect(button("Prev").disabled).toBe(true);
  await click("Next");
  expect(host.textContent).toContain("Showing 101–120");
  expect(host.textContent).toContain("Page 2");
  expect(button("Next").disabled).toBe(true);
  await click("Prev");
  expect(host.textContent).toContain("Showing 1–100");
});

it("shows an empty cursor continuation as 0–0 while keeping Previous available", async () => {
  await act(async () => root.render(<Pager page={4} pageSize={100} rowsOnPage={0} hasMore={false} onPage={() => {}} />));
  expect(host.textContent).toContain("Showing 0–0");
  expect(host.textContent).not.toContain("0–400");
  expect(host.textContent).not.toContain(" of ");
  expect(button("Next").disabled).toBe(true);
  expect(button("Prev").disabled).toBe(false);
});
