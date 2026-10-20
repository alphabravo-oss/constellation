import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { ChevronRight, MoveHorizontal } from "lucide-react";
import type { ColumnPinning } from "./data-table-arrangement";

const itemClass = "flex cursor-pointer select-none items-center justify-between gap-3 rounded-sm px-2 py-1.5 text-sm outline-none focus:bg-accent data-[disabled]:pointer-events-none data-[disabled]:opacity-40";
const menuClass = "z-popover min-w-52 rounded-md border border-border bg-popover p-1 text-popover-foreground shadow-elev-popover";

export function ColumnLayoutMenu({ columns, pinning, onMove, onPin, onResetWidth, onReset }: {
  columns: Array<{ id: string; label: string }>;
  pinning: ColumnPinning;
  onMove: (id: string, direction: -1 | 1) => void;
  onPin: (id: string, side: "start" | "end" | null) => void;
  onResetWidth: (id: string) => void;
  onReset: () => void;
}) {
  const unpinned = columns.filter(column => !pinning.start.includes(column.id) && !pinning.end.includes(column.id));
  return <DropdownMenu.Root>
    <DropdownMenu.Trigger asChild><button type="button" aria-label="Column layout" title="Column layout" className="inline-flex h-9 w-9 items-center justify-center rounded-md border border-border text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring"><MoveHorizontal className="h-4 w-4" /></button></DropdownMenu.Trigger>
    <DropdownMenu.Portal><DropdownMenu.Content align="end" sideOffset={6} className={menuClass}>
      <DropdownMenu.Label className="px-2 py-1.5 text-meta font-semibold text-muted-foreground">Arrange columns</DropdownMenu.Label>
      {columns.map(column => {
        const start = pinning.start.includes(column.id), end = pinning.end.includes(column.id);
        const index = unpinned.findIndex(item => item.id === column.id);
        return <DropdownMenu.Sub key={column.id}>
          <DropdownMenu.SubTrigger className={itemClass}><span>{column.label}{start ? " · pinned left" : end ? " · pinned right" : ""}</span><ChevronRight className="h-3 w-3" /></DropdownMenu.SubTrigger>
          <DropdownMenu.Portal><DropdownMenu.SubContent className={menuClass}>
            <DropdownMenu.Item className={itemClass} disabled={index <= 0} onSelect={() => onMove(column.id, -1)}>Move left</DropdownMenu.Item>
            <DropdownMenu.Item className={itemClass} disabled={index < 0 || index === unpinned.length - 1} onSelect={() => onMove(column.id, 1)}>Move right</DropdownMenu.Item>
            <DropdownMenu.Separator className="my-1 h-px bg-border" />
            <DropdownMenu.Item className={itemClass} disabled={start} onSelect={() => onPin(column.id, "start")}>Pin left</DropdownMenu.Item>
            <DropdownMenu.Item className={itemClass} disabled={end} onSelect={() => onPin(column.id, "end")}>Pin right</DropdownMenu.Item>
            <DropdownMenu.Item className={itemClass} disabled={!start && !end} onSelect={() => onPin(column.id, null)}>Unpin</DropdownMenu.Item>
            <DropdownMenu.Item className={itemClass} onSelect={() => onResetWidth(column.id)}>Reset width</DropdownMenu.Item>
          </DropdownMenu.SubContent></DropdownMenu.Portal>
        </DropdownMenu.Sub>;
      })}
      <DropdownMenu.Separator className="my-1 h-px bg-border" />
      <DropdownMenu.Item className={itemClass} onSelect={onReset}>Reset column layout</DropdownMenu.Item>
    </DropdownMenu.Content></DropdownMenu.Portal>
  </DropdownMenu.Root>;
}
