import {
  forwardRef,
  useId,
  useMemo,
  useState,
  type ComponentPropsWithoutRef,
  type FormHTMLAttributes,
  type InputHTMLAttributes,
  type ReactNode,
  type TextareaHTMLAttributes,
} from "react";
import {
  Checkbox as CheckboxPrimitive,
  Select as SelectPrimitive,
  Switch as SwitchPrimitive,
} from "radix-ui";
import { Command } from "cmdk";
import { Check, ChevronDown, ChevronsUpDown, Loader2 } from "lucide-react";
import { cn } from "../cn";
import { Popover, PopoverContent, PopoverTrigger } from "../primitives";

/* ------------------------------------------------------------------ */
/* Control chrome                                                      */
/* ------------------------------------------------------------------ */

/** Shared chrome for text inputs, selects and comboboxes (36 px). */
export const controlClassName =
  "flex h-(--control-h) w-full rounded-md border border-input bg-background px-3 text-sm text-foreground placeholder:text-muted-foreground focus:outline-hidden focus-visible:outline-hidden focus:ring-2 focus:ring-ring focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-60";

export const Input = forwardRef<
  HTMLInputElement,
  InputHTMLAttributes<HTMLInputElement>
>(({ className, type = "text", ...props }, ref) => (
  <input
    ref={ref}
    type={type}
    className={cn(controlClassName, className)}
    {...props}
  />
));
Input.displayName = "Input";

export const Textarea = forwardRef<
  HTMLTextAreaElement,
  TextareaHTMLAttributes<HTMLTextAreaElement>
>(({ className, ...props }, ref) => (
  <textarea
    ref={ref}
    className={cn(controlClassName, "h-auto min-h-24 py-2", className)}
    {...props}
  />
));
Textarea.displayName = "Textarea";

/* ------------------------------------------------------------------ */
/* Field                                                               */
/* ------------------------------------------------------------------ */

/** Label + control + helper/error. Children receive the generated id. */
export function Field({
  label,
  helper,
  error,
  required = false,
  id: idProp,
  children,
  className,
}: {
  label: ReactNode;
  helper?: ReactNode;
  error?: ReactNode;
  required?: boolean;
  id?: string;
  children: (ids: {
    id: string;
    "aria-describedby"?: string;
    "aria-invalid"?: boolean;
  }) => ReactNode;
  className?: string;
}) {
  const generated = useId();
  const id = idProp ?? generated;
  const helperId = helper ? `${id}-helper` : undefined;
  const errorId = error ? `${id}-error` : undefined;
  const describedBy = [errorId, helperId].filter(Boolean).join(" ") || undefined;
  return (
    <div className={cn("space-y-1.5", className)}>
      <label htmlFor={id} className="block text-sm font-medium text-foreground">
        {label}
        {required ? (
          <span aria-hidden="true" className="ml-0.5 text-status-error">
            *
          </span>
        ) : null}
      </label>
      {children({
        id,
        "aria-describedby": describedBy,
        "aria-invalid": error ? true : undefined,
      })}
      {error ? (
        <p id={errorId} role="alert" className="text-meta text-status-error">
          {error}
        </p>
      ) : helper ? (
        <p id={helperId} className="text-meta text-muted-foreground">
          {helper}
        </p>
      ) : null}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Select (Radix; no native chrome)                                    */
/* ------------------------------------------------------------------ */

export interface SelectOption {
  value: string;
  label: ReactNode;
  disabled?: boolean;
}

export const Select = forwardRef<
  HTMLButtonElement,
  {
    options: readonly SelectOption[];
    value: string | null | undefined;
    onValueChange: (value: string) => void;
    placeholder?: string;
    disabled?: boolean;
    id?: string;
    className?: string;
    "aria-label"?: string;
    "aria-describedby"?: string;
    "aria-invalid"?: boolean;
    name?: string;
  }
>(
  (
    {
      options,
      value,
      onValueChange,
      placeholder = "Select…",
      disabled,
      id,
      className,
      name,
      ...aria
    },
    ref,
  ) => (
    <SelectPrimitive.Root
      value={value ?? undefined}
      onValueChange={onValueChange}
      disabled={disabled}
      name={name}
    >
      <SelectPrimitive.Trigger
        ref={ref}
        id={id}
        {...aria}
        className={cn(
          controlClassName,
          "items-center justify-between gap-2 text-left data-[placeholder]:text-muted-foreground",
          className,
        )}
      >
        <span className="min-w-0 flex-1 truncate">
          <SelectPrimitive.Value placeholder={placeholder} />
        </span>
        <SelectPrimitive.Icon asChild>
          <ChevronDown className="h-4 w-4 shrink-0 text-muted-foreground" />
        </SelectPrimitive.Icon>
      </SelectPrimitive.Trigger>
      <SelectPrimitive.Portal>
        <SelectPrimitive.Content
          position="popper"
          sideOffset={4}
          className="z-popover max-h-72 min-w-(--radix-select-trigger-width) overflow-hidden rounded-md border border-border bg-popover text-popover-foreground shadow-elev-popover"
        >
          <SelectPrimitive.Viewport className="p-1">
            {options.map((option) => (
              <SelectPrimitive.Item
                key={option.value}
                value={option.value}
                disabled={option.disabled}
                className="relative flex cursor-default select-none items-center rounded-sm py-1.5 pl-8 pr-2 text-sm outline-none data-disabled:opacity-50 data-highlighted:bg-accent"
              >
                <span className="absolute left-2 flex h-4 w-4 items-center justify-center">
                  <SelectPrimitive.ItemIndicator>
                    <Check className="h-3.5 w-3.5" />
                  </SelectPrimitive.ItemIndicator>
                </span>
                <SelectPrimitive.ItemText>{option.label}</SelectPrimitive.ItemText>
              </SelectPrimitive.Item>
            ))}
          </SelectPrimitive.Viewport>
        </SelectPrimitive.Content>
      </SelectPrimitive.Portal>
    </SelectPrimitive.Root>
  ),
);
Select.displayName = "Select";

/* ------------------------------------------------------------------ */
/* Combobox (searchable single select)                                 */
/* ------------------------------------------------------------------ */

export interface ComboboxOption {
  value: string;
  label: string;
  description?: string;
}

export function Combobox({
  options,
  value,
  onValueChange,
  placeholder = "Select…",
  searchPlaceholder = "Search…",
  emptyText = "No results",
  loading = false,
  onSearchChange,
  disabled = false,
  id,
  className,
  ...aria
}: {
  options: readonly ComboboxOption[];
  value: string | null;
  onValueChange: (value: string) => void;
  placeholder?: string;
  searchPlaceholder?: string;
  emptyText?: string;
  loading?: boolean;
  /** Server-side search: when set, the caller filters. */
  onSearchChange?: (query: string) => void;
  disabled?: boolean;
  id?: string;
  className?: string;
  "aria-label"?: string;
  "aria-describedby"?: string;
  "aria-invalid"?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const listId = useId();
  const selected = options.find((option) => option.value === value);
  const visible = useMemo(() => {
    if (onSearchChange || !query.trim()) return options;
    const needle = query.toLowerCase();
    return options.filter(
      (option) =>
        option.label.toLowerCase().includes(needle) ||
        option.description?.toLowerCase().includes(needle),
    );
  }, [onSearchChange, options, query]);
  return (
    <Popover
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (!next) {
          setQuery("");
          onSearchChange?.("");
        }
      }}
    >
      <PopoverTrigger asChild>
        <button
          type="button"
          id={id}
          disabled={disabled}
          role="combobox"
          aria-expanded={open}
          aria-controls={listId}
          {...aria}
          className={cn(
            controlClassName,
            "items-center justify-between gap-2 text-left",
            !selected && "text-muted-foreground",
            className,
          )}
        >
          <span className="min-w-0 flex-1 truncate">
            {selected?.label ?? placeholder}
          </span>
          <ChevronsUpDown className="h-4 w-4 shrink-0 text-muted-foreground" />
        </button>
      </PopoverTrigger>
      <PopoverContent className="w-(--radix-popover-trigger-width) p-0">
        <Command shouldFilter={false}>
          <Command.Input
            value={query}
            onValueChange={(next) => {
              setQuery(next);
              onSearchChange?.(next);
            }}
            placeholder={searchPlaceholder}
            className="h-10 w-full border-b border-border bg-transparent px-3 text-sm outline-hidden placeholder:text-muted-foreground"
          />
          <Command.List id={listId} className="max-h-64 overflow-y-auto p-1">
            {loading ? (
              <div className="flex items-center gap-2 px-3 py-2 text-sm text-muted-foreground">
                <Loader2 className="h-3.5 w-3.5 animate-spin" /> Loading…
              </div>
            ) : visible.length === 0 ? (
              <p className="px-3 py-4 text-center text-sm text-muted-foreground">
                {emptyText}
              </p>
            ) : (
              visible.map((option) => (
                <Command.Item
                  key={option.value}
                  value={option.value}
                  onSelect={() => {
                    onValueChange(option.value);
                    setOpen(false);
                  }}
                  className="flex cursor-pointer items-center gap-2 rounded-sm px-2 py-1.5 text-sm data-[selected=true]:bg-accent"
                >
                  <Check
                    className={cn(
                      "h-3.5 w-3.5 shrink-0",
                      option.value === value ? "opacity-100" : "opacity-0",
                    )}
                  />
                  <span className="min-w-0">
                    <span className="block truncate">{option.label}</span>
                    {option.description ? (
                      <span className="block truncate text-meta text-muted-foreground">
                        {option.description}
                      </span>
                    ) : null}
                  </span>
                </Command.Item>
              ))
            )}
          </Command.List>
        </Command>
      </PopoverContent>
    </Popover>
  );
}

/* ------------------------------------------------------------------ */
/* Checkbox + Switch (Radix)                                           */
/* ------------------------------------------------------------------ */

export const Checkbox = forwardRef<
  HTMLButtonElement,
  ComponentPropsWithoutRef<typeof CheckboxPrimitive.Root>
>(({ className, ...props }, ref) => (
  <CheckboxPrimitive.Root
    ref={ref}
    className={cn(
      "flex h-4 w-4 shrink-0 items-center justify-center rounded-sm border border-input bg-background transition-colors data-[state=checked]:border-foreground data-[state=checked]:bg-foreground data-[state=checked]:text-background focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:cursor-not-allowed disabled:opacity-50",
      className,
    )}
    {...props}
  >
    <CheckboxPrimitive.Indicator>
      <Check className="h-3 w-3" strokeWidth={3} />
    </CheckboxPrimitive.Indicator>
  </CheckboxPrimitive.Root>
));
Checkbox.displayName = "Checkbox";

export const Switch = forwardRef<
  HTMLButtonElement,
  ComponentPropsWithoutRef<typeof SwitchPrimitive.Root> & { size?: "sm" | "md" }
>(({ className, size = "md", ...props }, ref) => (
  <SwitchPrimitive.Root
    ref={ref}
    className={cn(
      "relative inline-flex shrink-0 cursor-pointer items-center rounded-full border-2 border-transparent transition-colors data-[state=checked]:bg-status-success data-[state=unchecked]:bg-muted focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:cursor-not-allowed disabled:opacity-60",
      size === "sm" ? "h-5 w-9" : "h-6 w-11",
      className,
    )}
    {...props}
  >
    <SwitchPrimitive.Thumb
      className={cn(
        "pointer-events-none block rounded-full bg-white shadow-elev-1 transition-transform data-[state=unchecked]:translate-x-0",
        size === "sm"
          ? "h-3.5 w-3.5 data-[state=checked]:translate-x-4"
          : "h-5 w-5 data-[state=checked]:translate-x-5",
      )}
    />
  </SwitchPrimitive.Root>
));
Switch.displayName = "Switch";

/** Checkbox/switch with its label to the right. */
export function ChoiceRow({
  control,
  label,
  description,
  id,
  className,
}: {
  control: ReactNode;
  label: ReactNode;
  description?: ReactNode;
  id: string;
  className?: string;
}) {
  return (
    <div className={cn("flex items-start gap-3", className)}>
      <span className="mt-0.5">{control}</span>
      <label htmlFor={id} className="min-w-0 cursor-pointer">
        <span className="block text-sm text-foreground">{label}</span>
        {description ? (
          <span className="block text-meta text-muted-foreground">
            {description}
          </span>
        ) : null}
      </label>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* FormShell                                                           */
/* ------------------------------------------------------------------ */

/** Route-level form frame: sections + a sticky footer with the actions. */
export function FormShell({
  children,
  footer,
  className,
  ...props
}: FormHTMLAttributes<HTMLFormElement> & { footer?: ReactNode }) {
  return (
    <form className={cn("space-y-(--gap-section)", className)} {...props}>
      {children}
      {footer ? (
        <div className="sticky bottom-0 -mx-4 flex items-center justify-end gap-2 border-t border-border bg-background/95 px-4 py-3 backdrop-blur sm:-mx-(--content-gutter) sm:px-(--content-gutter)">
          {footer}
        </div>
      ) : null}
    </form>
  );
}

export function FormSection({
  title,
  description,
  children,
  className,
}: {
  title: ReactNode;
  description?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={cn("rounded-lg border border-border bg-card", className)}>
      <div className="border-b border-border px-5 py-4">
        <h2 className="text-section-title font-semibold text-foreground">
          {title}
        </h2>
        {description ? (
          <p className="mt-1 text-sm text-muted-foreground">{description}</p>
        ) : null}
      </div>
      <div className="space-y-4 px-5 py-4">{children}</div>
    </section>
  );
}
