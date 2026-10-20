// Test helpers for the single Export menu (kit ExportMenu, Radix dropdown).
import { act } from "react";

type Root = Document | Element;

/** Export ▾ triggers (menu buttons whose label starts with "Export"). */
export function exportTriggers(root: Root = document): HTMLButtonElement[] {
  return [...root.querySelectorAll<HTMLButtonElement>("button")].filter((button) => button.textContent?.trim().startsWith("Export") && button.getAttribute("aria-haspopup") === "menu");
}

export async function openExportMenu(root: Root = document, index = 0): Promise<void> {
  const trigger = exportTriggers(root)[index];
  if (!trigger) throw new Error("No Export menu trigger");
  if (trigger.getAttribute("aria-expanded") === "true") return;
  await act(async () => { trigger.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true })); });
}

export async function closeExportMenu(): Promise<void> {
  if (!document.querySelector('[role="menu"]')) return;
  await act(async () => { document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true })); });
}

export function exportItem(label: string): HTMLElement | undefined {
  return [...document.querySelectorAll<HTMLElement>('[role="menuitem"]')].find((item) => item.textContent?.includes(label));
}

function singleExport(label: string, root: Root): HTMLButtonElement | undefined {
  return [...root.querySelectorAll<HTMLButtonElement>("button")].find((button) => button.getAttribute("aria-label") === label || button.getAttribute("data-export-label") === label && button.getAttribute("aria-haspopup") !== "menu");
}

/** Open the Export menu and choose the option whose text contains `label`
 * (a table with one export scope renders a plain Export button instead). */
export async function chooseExport(label: string, root: Root = document, index = 0): Promise<void> {
  const single = !exportTriggers(root)[index] ? singleExport(label, root) : undefined;
  if (single) { await act(async () => { single.click(); }); return; }
  await openExportMenu(root, index);
  let item = exportItem(label);
  for (let attempt = 0; !item && attempt < 3; attempt += 1) {
    await act(async () => { await new Promise((resolve) => setTimeout(resolve, 20)); });
    if (!document.querySelector('[role="menu"]')) await openExportMenu(root, index);
    item = exportItem(label);
  }
  if (!item) throw new Error(`No export option ${label}`);
  await act(async () => { item.click(); });
}

/** Is the option disabled (opens and closes the menu)? */
export async function exportOptionDisabled(label: string, root: Root = document, index = 0): Promise<boolean> {
  await openExportMenu(root, index);
  const disabled = exportItem(label)?.hasAttribute("data-disabled") ?? false;
  await closeExportMenu();
  return disabled;
}

/** True when an Export menu exists and `label` is an enabled option. */
export async function exportAvailable(label: string, root: Root = document, index = 0): Promise<boolean> {
  if (!exportTriggers(root)[index]) { const single = singleExport(label, root); return !!single && !single.disabled; }
  await openExportMenu(root, index);
  const item = exportItem(label);
  const available = !!item && !item.hasAttribute("data-disabled");
  await closeExportMenu();
  return available;
}
