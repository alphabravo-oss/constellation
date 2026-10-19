import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { NetworkEnforcementStatus } from "./NetworkEnforcementStatus";

describe("network enforcement feedback", () => {
  it.each([
    [{state:"active",last_status:""}, "Policy application pending"],
    [{state:"active",last_status:"ok"}, "Policy applied (applier reported)"],
    [{state:"active",last_status:"error",last_error:'network policy refused: protected namespace "constellation-system"'}, "Protected workload; policy not applied"],
    [{state:"active",last_status:"error",last_error:"Forbidden"}, "Policy application failed: Forbidden"],
    [{state:"lifting",last_status:"error",last_error:"Forbidden"}, "Removal failed; policy may still be enforced: Forbidden"],
    [{state:"lifting",last_status:"ok"}, "Removal pending confirmation"],
    [{state:"lifting",last_status:""}, "Removal pending confirmation"],
    [{state:"removed",last_status:"ok"}, "Removal confirmed"],
    [{state:"unknown",last_status:"ok"}, "Enforcement state unknown"],
  ])("reports %j without claiming unconfirmed enforcement", (action, text) => {
    expect(renderToStaticMarkup(<NetworkEnforcementStatus action={action}/>)).toContain(text);
  });
});
