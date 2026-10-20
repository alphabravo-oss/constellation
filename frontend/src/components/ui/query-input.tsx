import { Search, X } from "lucide-react";
import { type InputHTMLAttributes, forwardRef, useId, useRef, useState } from "react";
import { cn } from "@/lib/cn";

/**
 * QueryInput — the table search field (kit TableSearch geometry) with the
 * query-DSL hints in a dropdown under the field instead of a "Try" chip rail.
 * `/` belongs to the command palette, so the field registers no global key.
 */
export interface QuerySuggestion {
  label: string;
  /** Text appended to the query when chosen (e.g. "severity:critical"). */
  value: string;
  description?: string;
}

export interface QueryInputProps extends Omit<InputHTMLAttributes<HTMLInputElement>, "size"> {
  /** @deprecated `/` opens the command palette. */
  showShortcut?: boolean;
  onClear?: () => void;
  size?: "sm" | "md";
  /** @deprecated `/` opens the command palette. */
  registerFocusKey?: boolean;
  suggestions?: QuerySuggestion[];
  onSuggestion?: (suggestion: QuerySuggestion) => void;
}

export const QueryInput = forwardRef<HTMLInputElement, QueryInputProps>(function QueryInput(
  { className, showShortcut: _showShortcut, onClear, value, size = "md", registerFocusKey: _registerFocusKey, suggestions, onSuggestion, onFocus, onBlur, onKeyDown, ...rest },
  ref,
) {
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const listId = useId();
  const blurTimer = useRef<number | null>(null);
  const hasSuggestions = !!suggestions?.length && !!onSuggestion;
  const showList = hasSuggestions && open;
  const choose = (suggestion: QuerySuggestion) => {
    onSuggestion?.(suggestion);
    setOpen(false);
  };
  return (
    <div className={cn("relative w-full", className)}>
      <div className={cn("relative flex w-full items-center rounded-md border border-input bg-background transition-colors focus-within:ring-2 focus-within:ring-ring", size === "sm" ? "h-8" : "h-9")}>
        <Search className={cn("pointer-events-none absolute left-3 text-muted-foreground", size === "sm" ? "h-3.5 w-3.5" : "h-4 w-4")} />
        <input
          ref={ref}
          type="text"
          value={value}
          role={hasSuggestions ? "combobox" : undefined}
          aria-expanded={hasSuggestions ? showList : undefined}
          aria-controls={hasSuggestions ? listId : undefined}
          aria-autocomplete={hasSuggestions ? "list" : undefined}
          className={cn(
            "w-full bg-transparent font-mono outline-none placeholder:font-sans placeholder:text-muted-foreground",
            size === "sm" ? "h-8 pl-8 pr-8 text-meta" : "h-9 pl-9 pr-9 text-sm",
          )}
          onFocus={(event) => {
            if (blurTimer.current) window.clearTimeout(blurTimer.current);
            setOpen(true);
            onFocus?.(event);
          }}
          onBlur={(event) => {
            blurTimer.current = window.setTimeout(() => setOpen(false), 120);
            onBlur?.(event);
          }}
          onKeyDown={(event) => {
            if (showList && suggestions) {
              if (event.key === "ArrowDown") { event.preventDefault(); setActive((index) => (index + 1) % suggestions.length); return; }
              if (event.key === "ArrowUp") { event.preventDefault(); setActive((index) => (index - 1 + suggestions.length) % suggestions.length); return; }
              if (event.key === "Escape") { setOpen(false); return; }
              if (event.key === "Tab" && !event.shiftKey && suggestions[active]) { event.preventDefault(); choose(suggestions[active]); return; }
            }
            onKeyDown?.(event);
          }}
          {...rest}
        />
        {value && onClear ? (
          <button
            type="button"
            onClick={onClear}
            aria-label="Clear search"
            className="absolute right-2 rounded-sm p-1 text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        ) : null}
      </div>
      {showList ? (
        <div
          id={listId}
          role="listbox"
          aria-label="Search suggestions"
          className="absolute left-0 right-0 top-full z-popover mt-1 overflow-hidden rounded-md border border-border bg-popover p-1 shadow-elev-popover"
          onMouseDown={(event) => event.preventDefault()}
          data-testid="query-suggestions"
        >
          <p className="px-2.5 py-1.5 text-meta font-semibold text-muted-foreground">Try a filter</p>
          {suggestions!.map((suggestion, index) => (
            <button
              key={suggestion.value}
              type="button"
              role="option"
              aria-selected={index === active}
              onMouseEnter={() => setActive(index)}
              onClick={() => choose(suggestion)}
              className={cn("flex w-full items-center justify-between gap-3 rounded-sm px-2.5 py-1.5 text-left text-sm", index === active && "bg-accent")}
            >
              <span className="font-mono text-13 text-foreground">{suggestion.value}</span>
              {suggestion.description ? <span className="truncate text-meta text-muted-foreground">{suggestion.description}</span> : null}
            </button>
          ))}
          <p className="border-t border-border px-2.5 py-1.5 text-micro text-muted-foreground">Tab inserts the highlighted filter · Esc closes</p>
        </div>
      ) : null}
    </div>
  );
});
