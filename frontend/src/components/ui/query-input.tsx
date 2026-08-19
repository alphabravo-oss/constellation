import { Search, X } from "lucide-react";
import { type InputHTMLAttributes, forwardRef, useRef, useEffect } from "react";
import { cn } from "@/lib/cn";
import { Kbd } from "./kbd";

/**
 * QueryInput — search input with DSL hint chips inline below.
 * Inspired by StackRox's Search query DSL.
 *
 * Layout: [icon] [free-text input] [/ kbd hint] [clear x]
 * Hints rail shown below if `hints` provided.
 */
export interface QueryInputProps extends Omit<InputHTMLAttributes<HTMLInputElement>, "size"> {
  showShortcut?: boolean;
  onClear?: () => void;
  size?: "sm" | "md";
  registerFocusKey?: boolean;
}

export const QueryInput = forwardRef<HTMLInputElement, QueryInputProps>(function QueryInput(
  { className, showShortcut = true, onClear, value, size = "md", registerFocusKey = true, ...rest },
  ref,
) {
  const localRef = useRef<HTMLInputElement | null>(null);
  // Combine refs
  const setRef = (n: HTMLInputElement | null) => {
    localRef.current = n;
    if (typeof ref === "function") ref(n);
    else if (ref) (ref as React.MutableRefObject<HTMLInputElement | null>).current = n;
  };

  useEffect(() => {
    if (!registerFocusKey) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "/" && !e.metaKey && !e.ctrlKey) {
        const tag = (e.target as HTMLElement | null)?.tagName;
        if (tag === "INPUT" || tag === "TEXTAREA") return;
        const editable = (e.target as HTMLElement | null)?.isContentEditable;
        if (editable) return;
        e.preventDefault();
        localRef.current?.focus();
        localRef.current?.select();
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [registerFocusKey]);

  return (
    <div
      className={cn(
        "relative flex items-center w-full rounded-md border border-input bg-card focus-within:border-[color:var(--color-primary)] focus-within:ring-1 focus-within:ring-[color:var(--color-primary)] transition-colors",
        size === "sm" ? "h-8" : "h-9",
        className,
      )}
    >
      <Search className={cn("absolute left-2.5 text-muted-foreground pointer-events-none", size === "sm" ? "h-3.5 w-3.5" : "h-4 w-4")} />
      <input
        ref={setRef}
        type="text"
        value={value}
        className={cn(
          "w-full bg-transparent outline-none placeholder:text-muted-foreground/70 text-mono",
          size === "sm" ? "h-8 pl-8 pr-16 text-xs" : "h-9 pl-9 pr-20 text-sm",
        )}
        {...rest}
      />
      <div className="absolute right-1.5 flex items-center gap-1">
        {value && onClear && (
          <button
            type="button"
            onClick={onClear}
            aria-label="Clear search"
            className="rounded hover:bg-muted p-1 text-muted-foreground hover:text-foreground transition-colors"
          >
            <X className="h-3 w-3" />
          </button>
        )}
        {showShortcut && !value && <Kbd combo="/" />}
      </div>
    </div>
  );
});
