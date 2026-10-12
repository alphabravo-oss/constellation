import { useRef } from "react";

/** Pointer and keyboard resizing share the same bounded width callback. */
export function ColumnResizeHandle({ label, width, min, max, onResize, onReset }: {
  label: string; width: number; min: number; max: number;
  onResize: (width: number) => void; onReset: () => void;
}) {
  const drag = useRef<{ pointer: number; start: number; width: number } | null>(null);
  const bounded = (next: number) => onResize(Math.round(Math.max(min, Math.min(max, next))));
  return <div role="separator" aria-orientation="vertical" aria-label={`Resize ${label}`}
    aria-valuemin={Math.round(min)} aria-valuemax={Math.round(max)} aria-valuenow={Math.round(width)}
    aria-valuetext={`${Math.round(width)} pixels`} tabIndex={0} className="app-table-resize"
    title="Drag or use Left/Right arrows to resize. Home/End sets minimum/maximum. Double-click to reset."
    onClick={event => event.stopPropagation()}
    onDoubleClick={event => { event.stopPropagation(); onReset(); }}
    onPointerDown={event => {
      if (event.button !== 0) return;
      event.preventDefault(); event.stopPropagation();
      drag.current = { pointer: event.pointerId, start: event.clientX, width };
      event.currentTarget.setPointerCapture(event.pointerId);
    }}
    onPointerMove={event => { const current = drag.current; if (current?.pointer === event.pointerId) bounded(current.width + event.clientX - current.start); }}
    onPointerUp={event => { if (drag.current?.pointer === event.pointerId) { drag.current = null; event.currentTarget.releasePointerCapture(event.pointerId); } }}
    onPointerCancel={() => { drag.current = null; }} onLostPointerCapture={() => { drag.current = null; }}
    onKeyDown={event => {
      if (event.altKey || event.ctrlKey || event.metaKey) return;
      if (!["ArrowLeft", "ArrowRight", "Home", "End", "Enter"].includes(event.key)) return;
      event.preventDefault(); event.stopPropagation();
      if (event.key === "Enter") onReset();
      else bounded(event.key === "Home" ? min : event.key === "End" ? max : width + (event.key === "ArrowRight" ? 1 : -1) * (event.shiftKey ? 40 : 16));
    }} />;
}
