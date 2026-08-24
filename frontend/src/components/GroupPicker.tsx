import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Check, CircleDashed, Search, ShieldCheck, UsersRound } from "lucide-react";

import { groupsApi, type Group } from "@/api/client";
import { cn } from "@/lib/cn";
import { filterGroupOptions, type GroupOption } from "@/lib/group-picker";

type GroupPickerProps = {
  clusterId?: string;
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
  required?: boolean;
  autoFocus?: boolean;
  placeholder?: string;
  allowExternal?: boolean;
  inputId?: string;
  testId?: string;
};

type GroupPickerViewProps = Omit<GroupPickerProps, "clusterId"> & {
  groups: Group[];
  isLoading?: boolean;
  isError?: boolean;
};

export function GroupPicker({
  clusterId,
  value,
  onChange,
  disabled,
  required,
  autoFocus,
  placeholder,
  allowExternal = true,
  inputId,
  testId,
}: GroupPickerProps) {
  const q = useQuery({
    queryKey: ["groups", clusterId],
    queryFn: () => groupsApi.list({ cluster_id: clusterId }),
    staleTime: 30_000,
  });

  return (
    <GroupPickerView
      value={value}
      onChange={onChange}
      disabled={disabled}
      required={required}
      autoFocus={autoFocus}
      placeholder={placeholder}
      allowExternal={allowExternal}
      inputId={inputId}
      testId={testId}
      groups={q.data?.groups ?? []}
      isLoading={q.isPending}
      isError={q.isError}
    />
  );
}

export function GroupPickerView({
  value,
  onChange,
  groups,
  disabled,
  required,
  autoFocus,
  placeholder = "Select group or type a name",
  allowExternal = true,
  inputId,
  testId = "group-picker",
  isLoading = false,
  isError = false,
}: GroupPickerViewProps) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState(value);
  const options = useMemo(
    () => isLoading || isError ? [] : filterGroupOptions(groups, query, allowExternal),
    [allowExternal, groups, isError, isLoading, query],
  );

  useEffect(() => {
    setQuery(value);
  }, [value]);

  const emptyMessage = isLoading
    ? "Loading groups..."
    : isError
      ? "Groups could not be loaded."
      : groups.length === 0
        ? "No groups available."
        : "No matching groups.";

  function commit(next: string) {
    setQuery(next);
    onChange(next);
    setOpen(false);
  }

  return (
    <div className="relative" data-testid={testId}>
      <div
        className={cn(
          "flex h-9 items-center gap-2 rounded-md border border-input bg-background px-3 shadow-[0_1px_1px_0_rgb(0_0_0/0.03)] transition-colors",
          "focus-within:border-[color:var(--color-brand)] focus-within:ring-2 focus-within:ring-[color:color-mix(in_oklab,var(--color-brand)_25%,transparent)]",
          disabled && "cursor-not-allowed opacity-50",
        )}
      >
        <Search className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden />
        <input
          id={inputId}
          role="combobox"
          aria-expanded={open}
          aria-controls={`${testId}-options`}
          aria-autocomplete="list"
          autoComplete="off"
          autoFocus={autoFocus}
          required={required}
          disabled={disabled}
          value={query}
          placeholder={placeholder}
          onFocus={() => !disabled && setOpen(true)}
          onBlur={() => window.setTimeout(() => setOpen(false), 100)}
          onChange={(e) => {
            setQuery(e.target.value);
            onChange(e.target.value);
            setOpen(true);
          }}
          className="h-full min-w-0 flex-1 bg-transparent text-sm text-foreground outline-none placeholder:text-muted-foreground/70 disabled:cursor-not-allowed"
        />
      </div>

      {open && !disabled && (
        <div
          id={`${testId}-options`}
          role="listbox"
          className="absolute z-40 mt-1 max-h-72 w-full overflow-auto rounded-md border border-border bg-popover p-1 shadow-xl"
        >
          {options.length === 0 ? (
            <div className="px-3 py-2 text-xs text-muted-foreground">{emptyMessage}</div>
          ) : (
            options.map((option) => (
              <GroupPickerOption
                key={option.type === "external" ? "external" : option.group.id}
                option={option}
                selected={option.name === value}
                onSelect={() => commit(option.name)}
              />
            ))
          )}
        </div>
      )}
    </div>
  );
}

function GroupPickerOption({ option, selected, onSelect }: { option: GroupOption; selected: boolean; onSelect: () => void }) {
  if (option.type === "external") {
    return (
      <button
        type="button"
        role="option"
        aria-selected={selected}
        onMouseDown={(e) => e.preventDefault()}
        onClick={onSelect}
        className="flex w-full items-center gap-2 rounded px-2 py-2 text-left text-sm hover:bg-accent"
      >
        <CircleDashed className="h-3.5 w-3.5 text-muted-foreground" aria-hidden />
        <span className="min-w-0 flex-1 font-medium">external</span>
        {selected ? <Check className="h-3.5 w-3.5 text-[color:var(--color-primary)]" aria-hidden /> : null}
      </button>
    );
  }

  const group = option.group;
  return (
    <button
      type="button"
      role="option"
      aria-selected={selected}
      onMouseDown={(e) => e.preventDefault()}
      onClick={onSelect}
      className="flex w-full items-start gap-2 rounded px-2 py-2 text-left hover:bg-accent"
    >
      <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden />
      <span className="min-w-0 flex-1">
        <span className="flex min-w-0 flex-wrap items-center gap-1.5">
          <span className="truncate text-sm font-medium text-foreground">{group.name}</span>
          <ModePill label="net" value={group.policy_mode} />
          <ModePill label="profile" value={group.profile_mode} />
        </span>
        <span className="mt-1 flex flex-wrap items-center gap-2 text-[11px] text-muted-foreground">
          <span className="capitalize">{group.kind}</span>
          <span className="inline-flex items-center gap-1">
            <UsersRound className="h-3 w-3" aria-hidden />
            {(group.members ?? []).length}
          </span>
          {(group.criteria ?? []).slice(0, 2).map((criterion) => (
            <span key={`${criterion.key}:${criterion.op}:${criterion.value}`} className="font-mono">
              {criterion.key}{criterion.op === "eq" ? "=" : ` ${criterion.op} `}{criterion.value}
            </span>
          ))}
        </span>
      </span>
      {selected ? <Check className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[color:var(--color-primary)]" aria-hidden /> : null}
    </button>
  );
}

function ModePill({ label, value }: { label: string; value?: string }) {
  const mode = (value || "discover").toLowerCase();
  return (
    <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">
      {label}:{mode}
    </span>
  );
}
