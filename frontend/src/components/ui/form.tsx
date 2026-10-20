import {
  Children,
  Fragment,
  isValidElement,
  useId,
  useMemo,
  useState,
  type ChangeEvent,
  type ComponentProps,
  type ReactElement,
  type ReactNode,
} from "react";
import { cn } from "@/lib/cn";
import { Form } from "@/ui";

/**
 * Form primitives on the kit field kit: one control height (--control-h), no
 * native control chrome anywhere.
 */
const controlBase = Form.controlClassName;

export function TextInput({ className, ...props }: ComponentProps<"input">) {
  return <input className={cn(controlBase, className)} {...props} />;
}

export function Textarea({ className, ...props }: ComponentProps<"textarea">) {
  return <textarea className={cn(controlBase, "h-auto min-h-20 py-2 leading-relaxed", className)} {...props} />;
}

// ─────────────── Select: native API, kit (Radix) control ───────────────

const EMPTY = "__constellation_empty__";

interface ParsedOption { value: string; label: ReactNode; disabled?: boolean; text: string }

function textContent(node: ReactNode): string {
  if (node == null || typeof node === "boolean") return "";
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(textContent).join("");
  if (isValidElement<{ children?: ReactNode }>(node)) return textContent(node.props.children);
  return "";
}

function parseOptions(children: ReactNode, out: ParsedOption[] = []): ParsedOption[] {
  Children.forEach(children, (child) => {
    if (!isValidElement(child)) return;
    const element = child as ReactElement<{ value?: string | number; children?: ReactNode; disabled?: boolean; label?: string }>;
    if (element.type === Fragment || element.type === "optgroup") {
      parseOptions(element.props.children, out);
      return;
    }
    if (element.type === "option") {
      const text = textContent(element.props.children) || element.props.label || "";
      const value = element.props.value !== undefined ? String(element.props.value) : text;
      out.push({ value, label: element.props.children ?? text, disabled: element.props.disabled, text });
    }
  });
  return out;
}

export type SelectProps = Omit<ComponentProps<"select">, "multiple" | "size"> & {
  /** Placeholder when the value matches no option. */
  placeholder?: string;
};

/**
 * Select keeps the native `<select>` API (`value`, `onChange(event)`,
 * `<option>` children) but renders the kit's Radix Select. A hidden native
 * mirror carries `name` for form submission and the same change contract for
 * programmatic callers; it is display:none and never focusable.
 */
export function Select({
  className,
  children,
  value,
  defaultValue,
  onChange,
  disabled,
  name,
  id,
  required,
  title,
  placeholder,
  "aria-label": ariaLabel,
  "aria-describedby": ariaDescribedBy,
  "aria-invalid": ariaInvalid,
  ...rest
}: SelectProps) {
  const options = useMemo(() => parseOptions(children), [children]);
  const [uncontrolled, setUncontrolled] = useState<string>(() => (defaultValue !== undefined ? String(defaultValue) : options[0]?.value ?? ""));
  const current = value !== undefined && value !== null ? String(value) : uncontrolled;
  const testId = (rest as Record<string, unknown>)["data-testid"] as string | undefined;
  const emit = (next: string) => {
    if (value === undefined) setUncontrolled(next);
    if (!onChange) return;
    const target = { value: next, name: name ?? "", id: id ?? "" } as unknown as HTMLSelectElement;
    onChange({ target, currentTarget: target, preventDefault() {}, stopPropagation() {} } as unknown as ChangeEvent<HTMLSelectElement>);
  };
  const kitOptions = options.map((option) => ({ value: option.value === "" ? EMPTY : option.value, label: option.label, disabled: option.disabled }));
  return (
    <>
      <select
        hidden
        aria-hidden="true"
        tabIndex={-1}
        data-native-mirror=""
        data-testid={testId}
        aria-label={ariaLabel}
        name={name}
        required={required}
        disabled={disabled}
        value={current}
        onChange={(event) => emit(event.target.value)}
      >
        {options.map((option) => (
          <option key={option.value} value={option.value} disabled={option.disabled}>{option.text}</option>
        ))}
      </select>
      <Form.Select
        id={id}
        options={kitOptions}
        value={current === "" ? (options.some((option) => option.value === "") ? EMPTY : "") : current}
        onValueChange={(next) => emit(next === EMPTY ? "" : next)}
        disabled={disabled}
        placeholder={placeholder}
        aria-label={ariaLabel ?? title}
        aria-describedby={ariaDescribedBy}
        aria-invalid={ariaInvalid === true || ariaInvalid === "true" ? true : undefined}
        className={cn("w-auto min-w-32 max-w-full", className)}
      />
    </>
  );
}

/**
 * Field — label + control + hint/error, the label wired to the control.
 */
export function Field({
  label,
  hint,
  error,
  required,
  htmlFor,
  children,
  className,
}: {
  label?: ReactNode;
  hint?: ReactNode;
  error?: ReactNode;
  required?: boolean;
  htmlFor?: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("space-y-1.5", className)}>
      {label && (
        <label htmlFor={htmlFor} className="block text-sm font-medium text-foreground">
          {label}
          {required && <span aria-hidden className="ml-0.5 text-status-error">*</span>}
        </label>
      )}
      {children}
      {error ? (
        <p className="text-meta text-status-error">{error}</p>
      ) : hint ? (
        <p className="text-meta text-muted-foreground">{hint}</p>
      ) : null}
    </div>
  );
}

/** Switch — the kit (Radix) switch, optionally with a label + description. */
export function Switch({
  checked,
  onCheckedChange,
  disabled,
  label,
  description,
  className,
}: {
  checked: boolean;
  onCheckedChange: (v: boolean) => void;
  disabled?: boolean;
  label?: ReactNode;
  description?: ReactNode;
  className?: string;
}) {
  const labelId = useId();
  const toggle = (
    <Form.Switch
      size="sm"
      checked={checked}
      onCheckedChange={onCheckedChange}
      disabled={disabled}
      aria-labelledby={label ? labelId : undefined}
      className={className}
    />
  );
  if (!label && !description) return toggle;
  return (
    <div className="flex items-center justify-between gap-4">
      <div className="min-w-0">
        {label && <div id={labelId} className="text-sm font-medium text-foreground">{label}</div>}
        {description && <div className="text-meta text-muted-foreground">{description}</div>}
      </div>
      {toggle}
    </div>
  );
}

/**
 * Checkbox with the native onChange contract (`event.target.checked`) on the
 * kit's Radix checkbox. Use for the remaining inline checkboxes.
 */
export function Checkbox({
  checked,
  onChange,
  disabled,
  className,
  id,
  name,
  "aria-label": ariaLabel,
  ...rest
}: Omit<ComponentProps<"input">, "type" | "checked"> & { checked?: boolean | "indeterminate" }) {
  const testId = (rest as Record<string, unknown>)["data-testid"] as string | undefined;
  const emit = (next: boolean) => {
    if (!onChange) return;
    const target = { checked: next, value: next ? "on" : "", name: name ?? "", id: id ?? "" } as unknown as HTMLInputElement;
    onChange({ target, currentTarget: target, preventDefault() {}, stopPropagation() {} } as unknown as ChangeEvent<HTMLInputElement>);
  };
  return (
    <Form.Checkbox
      id={id}
      name={name}
      checked={checked ?? false}
      onCheckedChange={(next) => emit(next === true)}
      onClick={(event) => event.stopPropagation()}
      disabled={disabled}
      aria-label={ariaLabel}
      data-testid={testId}
      className={className}
    />
  );
}
