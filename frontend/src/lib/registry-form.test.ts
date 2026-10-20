import { expect, it } from "vitest";
import { registryCredentialsForSave } from "./registry-form";
it("preserves saved credentials when fields remain blank, including cleared drafts", () => {
  expect(registryCredentialsForSave("static", {}, true)).toBeUndefined();
  expect(registryCredentialsForSave("static", { username: "", password: "" }, true)).toBeUndefined();
});
it("explicitly removes saved credentials when authentication is disabled", () => {
  expect(registryCredentialsForSave("none", { password: "old-draft" }, true)).toEqual({});
  expect(registryCredentialsForSave("none", { password: "old-draft" }, false)).toBeUndefined();
});
it("does not trim or expose a replacement password", () => {
  expect(registryCredentialsForSave("static", { username: "account", password: " spaces ", token: "" }, true)).toEqual({ username: "account", password: " spaces " });
});
