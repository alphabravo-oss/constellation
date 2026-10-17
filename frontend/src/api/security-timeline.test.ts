import { afterEach, expect, it, vi } from "vitest";
import { api, securityTimeline } from "./client";
afterEach(() => vi.restoreAllMocks());
it("exports the full exact event cohort without page bounds and reports truncation", async () => {
  const get = vi
    .spyOn(api, "get")
    .mockResolvedValue({
      data: new Blob(["id\nrecord\n"]),
      headers: {
        "x-export-total": "12000",
        "x-export-limit": "10000",
        "x-export-truncated": "true",
      },
    });
  vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:events");
  vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
  const click = vi
    .spyOn(HTMLAnchorElement.prototype, "click")
    .mockImplementation(() => {});
  const after = "2026-10-01T12:34:56.123456Z";
  await expect(
    securityTimeline.exportCSV({
      cluster_id: "cluster",
      type: "runtime_event",
      after,
      after_exclusive: true,
      severity: "high,critical",
      verdict: "alert,block,quarantine",
      limit: 100,
      offset: 500,
      q: "api",
    }),
  ).resolves.toEqual({
    total: 12000,
    exported: 10000,
    limit: 10000,
    truncated: true,
  });
  expect(get).toHaveBeenCalledWith("/security/timeline.csv", {
    params: {
      cluster_id: "cluster",
      type: "runtime_event",
      after,
      after_exclusive: true,
      severity: "high,critical",
      verdict: "alert,block,quarantine",
      q: "api",
    },
    responseType: "blob",
  });
  expect(click).toHaveBeenCalledOnce();
});
it.each([
  {},
  {
    "x-export-total": "1",
    "x-export-limit": "10000",
    "x-export-truncated": "true",
  },
  {
    "x-export-total": "",
    "x-export-limit": "10000",
    "x-export-truncated": "false",
  },
])(
  "rejects unconfirmed count/cap metadata without downloading",
  async (headers) => {
    vi.spyOn(api, "get").mockResolvedValue({
      data: new Blob(["id\n"]),
      headers,
    });
    const click = vi
      .spyOn(HTMLAnchorElement.prototype, "click")
      .mockImplementation(() => {});
    await expect(securityTimeline.exportCSV()).rejects.toThrow(
      "scope could not be confirmed",
    );
    expect(click).not.toHaveBeenCalled();
  },
);
