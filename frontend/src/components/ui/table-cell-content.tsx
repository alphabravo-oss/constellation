import { useLayoutEffect, useRef, useState, type ReactNode } from "react";
import * as Tooltip from "@radix-ui/react-tooltip";
import type { OverflowPolicy } from "./data-table-layout";

/** One overflow policy for every table; clipping never removes the full value. */
export function TableCellContent({ children, overflow, width }: { children: ReactNode; overflow: OverflowPolicy; width?: number }) {
  const ref = useRef<HTMLDivElement>(null);
  const [fullValue, setFullValue] = useState("");
  const clipping = overflow === "truncate" || overflow === "wrap-2" || overflow === "middle" || overflow === "nowrap";
  useLayoutEffect(() => {
    const element = ref.current;
    if (!clipping || !element) { setFullValue(""); return; }
    const clipped = element.scrollWidth > element.clientWidth + 1 || element.scrollHeight > element.clientHeight + 1
      || Array.from(element.querySelectorAll<HTMLElement>("*")).some((child) => child.clientWidth > 0
        && (child.scrollWidth > child.clientWidth + 1 || child.scrollHeight > child.clientHeight + 1));
    setFullValue(clipped ? element.textContent ?? "" : "");
  }, [children, clipping, width]);
  const content = <div ref={ref} className="app-table-cell-content" data-overflow={overflow}
    tabIndex={fullValue ? 0 : undefined}>{children}</div>;
  if (!clipping || !fullValue) return content;
  return <Tooltip.Provider delayDuration={250}><Tooltip.Root>
    <Tooltip.Trigger asChild>{content}</Tooltip.Trigger>
    <Tooltip.Portal><Tooltip.Content side="top" sideOffset={6}
      className="z-50 max-w-md whitespace-pre-wrap break-words rounded-md border border-border bg-popover px-3 py-2 text-xs text-popover-foreground shadow-lg">
      {fullValue}<Tooltip.Arrow className="fill-popover" />
    </Tooltip.Content></Tooltip.Portal>
  </Tooltip.Root></Tooltip.Provider>;
}
