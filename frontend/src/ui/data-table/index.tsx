import {
  useState,
  type ButtonHTMLAttributes,
  type ReactNode,
  type Ref,
} from "react";
import {
  Bookmark,
  Check,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Columns3,
  Download,
  Filter,
  MoreVertical,
  Rows3,
  Search,
  X,
} from "lucide-react";
import { cn } from "../cn";
import { useProduct } from "../product";
import {
  Menu,
  MenuCheckboxItem,
  MenuContent,
  MenuItem,
  MenuItemIndicator,
  MenuLabel,
  MenuSeparator,
  MenuTrigger,
  Popover,
  PopoverContent,
  PopoverTrigger,
  Tooltip,
} from "../primitives";

/**
 * Table chrome primitives. The product's TanStack Table wrapper composes
 * them; the kit owns the look (and the "one Export verb" rule).
 *
 *   <TableToolbar
 *     search={<TableSearch … />}
 *     filters={<>…<MoreFilters>…</MoreFilters></>}
 *     chips={<FilterChips …/>}
 *     actions={<>{views}<ColumnMenu …/><DensityToggle …/><ExportMenu …/></>}
 *   />
 */
export function TableToolbar({
  search,
  filters,
  chips,
  actions,
  className,
}: {
  search?: ReactNode;
  filters?: ReactNode;
  chips?: ReactNode;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("space-y-2", className)}>
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex min-w-0 flex-1 flex-wrap items-center gap-2">
          {search}
          {filters}
        </div>
        {actions ? (
          <div className="flex shrink-0 items-center gap-2 self-end sm:self-auto">
            {actions}
          </div>
        ) : null}
      </div>
      {chips}
    </div>
  );
}

export function TableSearch({
  value,
  onChange,
  placeholder = "Search…",
  inputRef,
  className,
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  inputRef?: Ref<HTMLInputElement>;
  className?: string;
}) {
  return (
    <div className={cn("relative w-full max-w-sm", className)}>
      <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
      <input
        ref={inputRef}
        type="text"
        data-table-search=""
        aria-label={placeholder}
        placeholder={placeholder}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="h-9 w-full rounded-md border border-border bg-background pl-9 pr-8 text-sm placeholder:text-muted-foreground focus:outline-hidden focus:ring-2 focus:ring-ring"
      />
      {value ? (
        <button
          type="button"
          aria-label="Clear search"
          onClick={() => onChange("")}
          className="absolute right-2.5 top-1/2 -translate-y-1/2 rounded-sm text-muted-foreground hover:text-foreground focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring"
        >
          <X className="h-3.5 w-3.5" />
        </button>
      ) : null}
    </div>
  );
}

/** A 36 px toolbar button (filters, views, columns…). */
export function ToolbarButton({
  active = false,
  className,
  children,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { active?: boolean }) {
  return (
    <button
      type="button"
      className={cn(
        "inline-flex h-9 items-center gap-1.5 rounded-md border px-3 text-sm transition-colors focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50",
        active
          ? "border-foreground/40 bg-accent text-foreground"
          : "border-border text-muted-foreground hover:bg-accent hover:text-foreground",
        className,
      )}
      {...props}
    >
      {children}
    </button>
  );
}

/** Removable filter chip ("Status: Active ×"). */
export function FilterChip({
  label,
  value,
  onRemove,
}: {
  label: string;
  value: ReactNode;
  onRemove?: () => void;
}) {
  return (
    <span className="inline-flex h-7 items-center gap-1 rounded-full border border-border bg-muted/40 pl-2.5 pr-1 text-meta text-foreground">
      <span className="text-muted-foreground">{label}:</span>
      <span className="font-medium">{value}</span>
      {onRemove ? (
        <button
          type="button"
          aria-label={`Remove ${label} filter`}
          onClick={onRemove}
          className="ml-0.5 rounded-full p-0.5 text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring"
        >
          <X className="h-3 w-3" />
        </button>
      ) : null}
    </span>
  );
}

export function FilterChips({
  children,
  onClearAll,
  className,
}: {
  children: ReactNode;
  onClearAll?: () => void;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-wrap items-center gap-1.5", className)}>
      {children}
      {onClearAll ? (
        <button
          type="button"
          onClick={onClearAll}
          className="h-7 rounded-md px-2 text-meta text-muted-foreground hover:text-foreground focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring"
        >
          Clear all
        </button>
      ) : null}
    </div>
  );
}

/** Overflow for filters beyond the first three: a popover with the rest. */
export function MoreFilters({
  count = 0,
  children,
}: {
  /** Number of active filters inside, shown as a badge. */
  count?: number;
  children: ReactNode;
}) {
  return (
    <Popover>
      <PopoverTrigger asChild>
        <ToolbarButton active={count > 0}>
          <Filter className="h-3.5 w-3.5" />
          More filters
          {count > 0 ? (
            <span className="ml-0.5 inline-flex h-5 min-w-5 items-center justify-center rounded-full bg-foreground px-1 text-micro text-background">
              {count}
            </span>
          ) : null}
        </ToolbarButton>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-80 space-y-3">
        {children}
      </PopoverContent>
    </Popover>
  );
}

export interface ExportOption {
  label: string;
  description?: string;
  onSelect: () => void;
  disabled?: boolean;
}

/** The single export verb: `Export ▾` with the available scopes. */
export function ExportMenu({ options }: { options: ExportOption[] }) {
  if (options.length === 0) return null;
  if (options.length === 1) {
    return (
      <Tooltip content={options[0].description}>
        <ToolbarButton
          onClick={options[0].onSelect}
          disabled={options[0].disabled}
        >
          <Download className="h-4 w-4" />
          Export
        </ToolbarButton>
      </Tooltip>
    );
  }
  return (
    <Menu modal={false}>
      <MenuTrigger asChild>
        <ToolbarButton>
          <Download className="h-4 w-4" />
          Export
          <ChevronDown className="h-3 w-3 text-muted-foreground" aria-hidden />
        </ToolbarButton>
      </MenuTrigger>
      <MenuContent className="w-64">
        <MenuLabel>Export as CSV</MenuLabel>
        {options.map((option) => (
          <MenuItem
            key={option.label}
            disabled={option.disabled}
            onSelect={option.onSelect}
            className="flex-col items-start gap-0"
          >
            <span>{option.label}</span>
            {option.description ? (
              <span className="text-meta text-muted-foreground">
                {option.description}
              </span>
            ) : null}
          </MenuItem>
        ))}
      </MenuContent>
    </Menu>
  );
}

export interface ColumnMenuEntry {
  key: string;
  label: string;
  visible: boolean;
  hideable?: boolean;
}

/** Column visibility menu (checkbox list) with an optional reset. */
export function ColumnMenu({
  columns,
  onToggle,
  onReset,
}: {
  columns: ColumnMenuEntry[];
  onToggle: (key: string, visible: boolean) => void;
  onReset?: () => void;
}) {
  return (
    <Menu modal={false}>
      <MenuTrigger asChild>
        <ToolbarButton>
          <Columns3 className="h-4 w-4" />
          Columns
        </ToolbarButton>
      </MenuTrigger>
      <MenuContent className="w-60">
        {columns
          .filter((column) => column.hideable !== false)
          .map((column) => (
            <MenuCheckboxItem
              key={column.key}
              checked={column.visible}
              onCheckedChange={(checked) =>
                onToggle(column.key, checked === true)
              }
              onSelect={(event) => event.preventDefault()}
              className="flex cursor-default select-none items-center gap-2 rounded-sm px-2 py-1.5 text-body outline-none data-highlighted:bg-accent"
            >
              <span className="flex h-4 w-4 items-center justify-center rounded-sm border border-input">
                <MenuItemIndicator>
                  <Check className="h-3 w-3" />
                </MenuItemIndicator>
              </span>
              <span className="truncate">{column.label}</span>
            </MenuCheckboxItem>
          ))}
        {onReset ? (
          <>
            <MenuSeparator />
            <MenuItem onSelect={onReset}>Reset columns</MenuItem>
          </>
        ) : null}
      </MenuContent>
    </Menu>
  );
}

export type Density = "comfortable" | "compact";

export function DensityToggle({
  value,
  onChange,
}: {
  value: Density;
  onChange: (next: Density) => void;
}) {
  const next: Density = value === "compact" ? "comfortable" : "compact";
  return (
    <Tooltip content={`Switch to ${next} rows`}>
      <ToolbarButton
        aria-label={`Row density: ${value}. Switch to ${next}`}
        aria-pressed={value === "compact"}
        onClick={() => onChange(next)}
        className="px-2.5"
      >
        <Rows3 className="h-4 w-4" />
      </ToolbarButton>
    </Tooltip>
  );
}

export interface SavedView {
  id: string;
  name: string;
}

/** Saved views: pick, save current, delete. */
export function SavedViewsMenu({
  views,
  activeId,
  onSelect,
  onSave,
  onDelete,
}: {
  views: SavedView[];
  activeId?: string | null;
  onSelect: (id: string | null) => void;
  onSave?: () => void;
  onDelete?: (id: string) => void;
}) {
  const active = views.find((view) => view.id === activeId);
  return (
    <Menu modal={false}>
      <MenuTrigger asChild>
        <ToolbarButton active={!!active}>
          <Bookmark className="h-4 w-4" />
          {active ? active.name : "Views"}
        </ToolbarButton>
      </MenuTrigger>
      <MenuContent className="w-60">
        <MenuItem onSelect={() => onSelect(null)}>Default view</MenuItem>
        {views.length > 0 ? <MenuSeparator /> : null}
        {views.map((view) => (
          <MenuItem key={view.id} onSelect={() => onSelect(view.id)}>
            <span className="min-w-0 flex-1 truncate">{view.name}</span>
            {view.id === activeId ? <Check className="h-3.5 w-3.5" /> : null}
            {onDelete ? (
              <button
                type="button"
                aria-label={`Delete view ${view.name}`}
                onClick={(event) => {
                  event.stopPropagation();
                  event.preventDefault();
                  onDelete(view.id);
                }}
                className="rounded-sm p-0.5 text-muted-foreground hover:text-foreground"
              >
                <X className="h-3 w-3" />
              </button>
            ) : null}
          </MenuItem>
        ))}
        {onSave ? (
          <>
            <MenuSeparator />
            <MenuItem onSelect={onSave}>Save current view…</MenuItem>
          </>
        ) : null}
      </MenuContent>
    </Menu>
  );
}

/** "Showing 1–20 of 212" + prev/next and a page list. */
export function Pagination({
  page,
  pageSize,
  pageCount,
  rowCount,
  currentRowCount,
  lowerBound = false,
  countUnknown = false,
  onPage,
  className,
}: {
  page: number;
  pageSize: number;
  pageCount: number;
  rowCount: number;
  currentRowCount: number;
  lowerBound?: boolean;
  countUnknown?: boolean;
  onPage: (page: number) => void;
  className?: string;
}) {
  if (pageCount <= 1 && page === 0) return null;
  const first = Math.max(0, Math.min(page - 2, pageCount - 5));
  const visible = Array.from({ length: Math.min(pageCount, 5) }, (_, i) =>
    pageCount <= 5 ? i : first + i,
  );
  const from = currentRowCount === 0 ? 0 : page * pageSize + 1;
  const to = currentRowCount === 0 ? 0 : page * pageSize + currentRowCount;
  return (
    <div className={cn("flex items-center justify-between text-sm", className)}>
      <span className="text-muted-foreground tabular-nums">
        {countUnknown
          ? `Rows ${from}–${to}`
          : `Showing ${from}–${to} of ${lowerBound ? "at least " : ""}${rowCount.toLocaleString()}`}
      </span>
      <nav aria-label="Pagination" className="flex items-center gap-1">
        <PageButton
          aria-label="Previous page"
          disabled={page === 0}
          onClick={() => onPage(page - 1)}
        >
          <ChevronLeft className="h-4 w-4" />
        </PageButton>
        {visible.map((number) => (
          <PageButton
            key={number}
            aria-label={`Page ${number + 1}`}
            aria-current={number === page ? "page" : undefined}
            active={number === page}
            onClick={() => onPage(number)}
          >
            {number + 1}
          </PageButton>
        ))}
        <PageButton
          aria-label="Next page"
          disabled={page >= pageCount - 1}
          onClick={() => onPage(page + 1)}
        >
          <ChevronRight className="h-4 w-4" />
        </PageButton>
      </nav>
    </div>
  );
}

function PageButton({
  active = false,
  className,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { active?: boolean }) {
  return (
    <button
      type="button"
      className={cn(
        "inline-flex h-8 min-w-8 items-center justify-center rounded-md px-1 text-sm tabular-nums transition-colors focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50",
        active
          ? "bg-foreground text-background"
          : "text-muted-foreground hover:bg-accent hover:text-foreground",
        className,
      )}
      {...props}
    />
  );
}

export interface RowAction {
  label: string;
  icon?: ReactNode;
  onSelect: () => void;
  destructive?: boolean;
  disabled?: boolean;
  disabledReason?: string;
  separator?: boolean;
}

/** Row kebab (⋮) menu; the trigger never bubbles to a row click. */
export function RowActions({
  actions,
  label = "Row actions",
}: {
  actions: RowAction[];
  label?: string;
}) {
  const [open, setOpen] = useState(false);
  return (
    <Menu open={open} onOpenChange={setOpen} modal={false}>
      <MenuTrigger asChild>
        <button
          type="button"
          aria-label={label}
          onClick={(event) => event.stopPropagation()}
          className="inline-flex h-7 w-7 items-center justify-center rounded-sm text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring"
        >
          <MoreVertical className="h-4 w-4" />
        </button>
      </MenuTrigger>
      <MenuContent
        className="w-52"
        onClick={(event) => event.stopPropagation()}
      >
        {actions.map((action, index) => (
          <div key={`${action.label}-${index}`}>
            {action.separator && index > 0 ? <MenuSeparator /> : null}
            <MenuItem
              disabled={action.disabled}
              variant={action.destructive ? "destructive" : "default"}
              onSelect={action.onSelect}
              title={action.disabled ? action.disabledReason : undefined}
            >
              {action.icon}
              {action.label}
            </MenuItem>
          </div>
        ))}
      </MenuContent>
    </Menu>
  );
}

/**
 * Generated Kubernetes names wrap at their natural joints: a <wbr> after
 * every "-", "." and "/" so `astronomer-delivery-system` breaks as
 * `astronomer-delivery-` / `system`, never mid-word.
 */
export function breakableName(name: string): ReactNode {
  const parts = name.split(/(?<=[-./])/);
  if (parts.length < 2) return name;
  return parts.map((part, index) => (
    <span key={index}>
      {part}
      {index < parts.length - 1 ? <wbr /> : null}
    </span>
  ));
}

/**
 * Entity link: the full identifier, never truncated. Shows the complete
 * name (and an optional secondary line such as the namespace) in a tooltip
 * so long generated names stay copyable.
 */
export function EntityLink({
  to,
  name,
  secondary,
  mono = false,
  className,
  onClick,
}: {
  to: string;
  name: string;
  secondary?: ReactNode;
  mono?: boolean;
  className?: string;
  onClick?: (event: React.MouseEvent<HTMLAnchorElement>) => void;
}) {
  const { Link } = useProduct();
  return (
    <Tooltip
      content={
        <span className="block max-w-sm break-all font-mono text-micro">
          {name}
          {secondary ? (
            <span className="block text-muted-foreground">{secondary}</span>
          ) : null}
        </span>
      }
    >
      <Link
        to={to}
        onClick={onClick}
        className={cn(
          "app-table-entity-link inline",
          mono && "font-mono text-13",
          className,
        )}
      >
        {breakableName(name)}
      </Link>
    </Tooltip>
  );
}

/** Plain identifier (no link) that is never truncated. */
export function EntityName({
  name,
  mono = true,
  className,
}: {
  name: string;
  mono?: boolean;
  className?: string;
}) {
  return (
    <Tooltip
      content={<span className="break-all font-mono text-micro">{name}</span>}
    >
      <span
        className={cn(
          "inline text-foreground",
          mono && "font-mono text-13",
          className,
        )}
      >
        {breakableName(name)}
      </span>
    </Tooltip>
  );
}
