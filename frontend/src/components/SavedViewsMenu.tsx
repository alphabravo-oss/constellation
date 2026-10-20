import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { Bookmark, Trash2 } from "lucide-react";
import type { SavedViewBase } from "@/hooks/useSavedViews";
import { Button } from "@/components/ui/button";

/** Shared keyboard navigation, dismissal and focus return for named views. */
export function SavedViewsMenu<T extends SavedViewBase>({ views, onApply, onDelete, summary, testId }: {
  views: T[];
  onApply: (view: T) => void;
  onDelete: (id: string) => void;
  summary: (view: T) => string;
  testId?: string;
}) {
  return <DropdownMenu.Root>
    <DropdownMenu.Trigger asChild>
      <Button type="button" size="sm" variant="outline">
        <Bookmark className="h-3.5 w-3.5" aria-hidden /> Views <span className="font-mono text-muted-foreground">({views.length})</span>
      </Button>
    </DropdownMenu.Trigger>
    <DropdownMenu.Portal>
      <DropdownMenu.Content align="end" sideOffset={6} data-testid={testId} aria-label="Saved views"
        className="z-50 max-h-[min(24rem,var(--radix-dropdown-menu-content-available-height))] w-72 max-w-[calc(100vw-2rem)] overflow-auto rounded-md border border-border bg-popover p-1 shadow-xl">
        {!views.length && <DropdownMenu.Item disabled className="px-2 py-3 text-xs text-muted-foreground">No saved views</DropdownMenu.Item>}
        {views.map(view => <DropdownMenu.Group key={view.id} className="flex items-center gap-1">
          <DropdownMenu.Item asChild onSelect={() => onApply(view)} textValue={view.name}>
            <button type="button" aria-label={`Apply view ${view.name}`} className="min-w-0 flex-1 rounded px-2 py-2 text-left text-xs outline-none focus:bg-accent">
              <span className="block break-words font-medium">{view.name}</span>
              <span className="block truncate text-micro text-muted-foreground">{summary(view)}</span>
            </button>
          </DropdownMenu.Item>
          <DropdownMenu.Item asChild onSelect={() => onDelete(view.id)} textValue={`Delete ${view.name}`}>
            <button type="button" aria-label={`Delete view ${view.name}`} className="shrink-0 rounded p-2 text-muted-foreground outline-none focus:bg-accent focus:text-foreground">
              <Trash2 className="h-3.5 w-3.5" aria-hidden />
            </button>
          </DropdownMenu.Item>
        </DropdownMenu.Group>)}
      </DropdownMenu.Content>
    </DropdownMenu.Portal>
  </DropdownMenu.Root>;
}
