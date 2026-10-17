import { expect, it } from "vitest";
import { loginReturnPath } from "./login-return";

it.each([null, "", "https://outside.test", "//outside.test", "/\\outside.test", "/\n/outside.test", "javascript:alert(1)"])("rejects external login return %s", (input) => {
  expect(loginReturnPath(input)).toBe("/clusters");
});
it("keeps a local deep link with filters and fragment", () => {
  expect(loginReturnPath("/clusters/one/findings?severity=high#evidence")).toBe("/clusters/one/findings?severity=high#evidence");
});
