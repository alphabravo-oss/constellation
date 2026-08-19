import { afterEach, describe, expect, it, vi } from "vitest";

import { network, type NetworkStreamFlow } from "./client";

// NET-1: the SSE consumer parses text/event-stream frames out of a fetch
// ReadableStream. This test pins the frame-splitting logic: only `event: flow`
// frames are surfaced (ping comments and other events are ignored), even when a
// single chunk carries several frames or a frame is split across chunks.
function streamFromChunks(chunks: string[]): ReadableStream<Uint8Array> {
  const enc = new TextEncoder();
  let i = 0;
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      if (i < chunks.length) {
        controller.enqueue(enc.encode(chunks[i++]));
      } else {
        controller.close();
      }
    },
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("network.streamFlows", () => {
  it("emits only flow events and ignores pings/other events", async () => {
    const flow: NetworkStreamFlow = {
      cluster_id: "c1",
      src_workload: "ns/a",
      dst_workload: "ns/b",
      protocol: "tcp",
      port: 443,
      at: "2026-06-22T00:00:00Z",
    };
    const chunks = [
      ": ping\n\n",
      "event: flow\ndata: " + JSON.stringify(flow) + "\n\n",
      "event: other\ndata: {\"ignored\":true}\n\n",
      // a flow frame split across two chunks
      "event: flow\ndata: ",
      JSON.stringify({ ...flow, port: 8080 }) + "\n\n",
    ];

    const fetchMock = vi.fn(async () =>
      new Response(streamFromChunks(chunks), {
        status: 200,
        headers: { "Content-Type": "text/event-stream" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const seen: NetworkStreamFlow[] = [];
    const unsubscribe = network.streamFlows({ cluster_id: "c1" }, (f) => seen.push(f));

    // Let the async reader drain the stream.
    await vi.waitFor(() => expect(seen.length).toBe(2));
    unsubscribe();

    expect(seen[0].port).toBe(443);
    expect(seen[1].port).toBe(8080);
    // cluster_id is threaded into the request URL.
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/network/flows:stream?cluster_id=c1",
      expect.objectContaining({ credentials: "include" }),
    );
  });
});
