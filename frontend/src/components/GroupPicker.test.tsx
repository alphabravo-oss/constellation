import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";

import { GroupPickerView } from "./GroupPicker";
import type { Group } from "@/api/client";
import { filterGroupOptions } from "@/lib/group-picker";

const groups: Group[] = [
  {
    id: "g-api",
    name: "prod/api",
    kind: "learned",
    comment: "Handles checkout payments",
    criteria: [{ key: "app", op: "eq", value: "api" }],
    members: ["prod/api-7f99d", "prod/payment-worker"],
    learned_from: "",
    cfg_type: "user_created",
    policy_mode: "monitor",
    profile_mode: "discover",
  },
  {
    id: "g-db",
    name: "prod/db",
    kind: "learned",
    comment: "Postgres",
    criteria: [{ key: "role", op: "contains", value: "database" }],
    members: ["prod/db-0"],
    learned_from: "",
    cfg_type: "user_created",
    policy_mode: "protect",
    profile_mode: "protect",
  },
];

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

describe("GroupPicker", () => {
  it("filters by name, comment, criteria, and members", () => {
    expect(optionNames(filterGroupOptions(groups, "prod/a"))).toEqual(["prod/api"]);
    expect(optionNames(filterGroupOptions(groups, "checkout"))).toEqual(["prod/api"]);
    expect(optionNames(filterGroupOptions(groups, "database"))).toEqual(["prod/db"]);
    expect(optionNames(filterGroupOptions(groups, "payment-worker"))).toEqual(["prod/api"]);
  });

  it("keeps external available when it matches the query", () => {
    expect(optionNames(filterGroupOptions(groups, "ext"))).toEqual(["external"]);
  });

  it("renders loading, error, and empty states", () => {
    render(<GroupPickerView value="" onChange={() => undefined} groups={[]} isLoading />);
    focusInput();
    expect(host?.textContent).toContain("Loading groups...");

    render(<GroupPickerView value="" onChange={() => undefined} groups={[]} isError />);
    focusInput();
    expect(host?.textContent).toContain("Groups could not be loaded.");

    render(<GroupPickerView value="" onChange={() => undefined} groups={[]} allowExternal={false} />);
    focusInput();
    expect(host?.textContent).toContain("No groups available.");
  });

  it("selects a group and displays mode/member context", () => {
    const onChange = vi.fn();
    render(<GroupPickerView value="" onChange={onChange} groups={groups} allowExternal={false} />);

    focusInput();
    expect(host?.textContent).toContain("prod/api");
    expect(host?.textContent).toContain("net:monitor");
    expect(host?.textContent).toContain("profile:discover");
    expect(host?.textContent).toContain("app=api");

    act(() => {
      optionButton("prod/api")?.click();
    });

    expect(onChange).toHaveBeenLastCalledWith("prod/api");
    expect(input().value).toBe("prod/api");
  });
});

function optionNames(options: ReturnType<typeof filterGroupOptions>) {
  return options.map((option) => option.name);
}

function render(ui: ReactNode) {
  if (root) {
    act(() => root?.unmount());
  }
  host?.remove();
  host = document.createElement("div");
  document.body.appendChild(host);
  root = createRoot(host);
  act(() => {
    root?.render(ui);
  });
}

function input() {
  return host?.querySelector<HTMLInputElement>("[role='combobox']") as HTMLInputElement;
}

function focusInput() {
  act(() => {
    input().focus();
  });
}

function optionButton(text: string) {
  return Array.from(host?.querySelectorAll<HTMLButtonElement>("[role='option']") ?? []).find((button) => button.textContent?.includes(text));
}
