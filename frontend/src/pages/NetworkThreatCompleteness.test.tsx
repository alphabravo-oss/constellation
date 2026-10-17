import { renderToStaticMarkup } from "react-dom/server";
import { expect, it } from "vitest";
import { ThreatMaximum } from "./NetworkSecondaryInventory";

it("keeps a known high observed ID while disclosing unavailable historical maximum", () => {
  const html = renderToStaticMarkup(<ThreatMaximum id={4294967295} complete={false} />);
  expect(html).toContain("4294967295");
  expect(html).toContain("Historical maximum unavailable");
  expect(html).toContain("cannot prove");
});
it("never presents an uncertain old zero as proof that no threats were detected", () => {
  const html = renderToStaticMarkup(<ThreatMaximum id={0} complete={false} />);
  expect(html).toContain("Not reported");
  expect(html).toContain("Historical maximum unavailable");
  expect(html).not.toMatch(/No.*threat/i);
});
it("treats missing legacy metadata as unverified and displays a proven maximum without that qualifier", () => {
  expect(renderToStaticMarkup(<ThreatMaximum id={2147483648} />)).toContain("Maximum unverified");
  const proven = renderToStaticMarkup(<ThreatMaximum id={2147483648} complete />);
  expect(proven).toContain("2147483648");
  expect(proven).not.toMatch(/unverified|unavailable/);
});
