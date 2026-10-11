import { useId, type ReactNode } from "react";
import { useFieldContext, useFormContext } from "@/lib/form-context";
import { Field, TextInput } from "@/components/ui/form";
import { Button } from "@/components/ui/button";

export function NumberField({ label, hint, min, max }: { label: string; hint?: string; min?: number; max?: number }) {
  const field = useFieldContext<number>();
  const id = useId();
  const errors = field.state.meta.isTouched ? field.state.meta.errors : [];
  const error = errors.map((e: unknown) => typeof e === "string" ? e : (e as { message?: string })?.message).filter(Boolean).join("; ");
  return (
    <Field label={label} htmlFor={id} hint={hint && <span id={`${id}-hint`}>{hint}</span>}
      error={error && <span id={`${id}-error`}>{error}</span>}>
      <TextInput id={id} name={field.name} type="number" min={min} max={max} step={1}
        value={Number.isFinite(field.state.value) ? field.state.value : ""}
        onChange={(e) => field.handleChange(e.target.valueAsNumber)} onBlur={field.handleBlur}
        aria-invalid={Boolean(error)} aria-describedby={error ? `${id}-error` : hint ? `${id}-hint` : undefined}
        className="w-40" />
    </Field>
  );
}

export function SubmitButton({ children }: { children: ReactNode }) {
  const form = useFormContext();
  return <form.Subscribe selector={(state) => [state.canSubmit, state.isSubmitting]}>
    {([canSubmit, isSubmitting]) => <Button type="submit" variant="primary" size="lg" disabled={!canSubmit || isSubmitting}>
      {isSubmitting ? "Saving…" : children}
    </Button>}
  </form.Subscribe>;
}
