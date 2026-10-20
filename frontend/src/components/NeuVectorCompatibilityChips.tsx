import { Link } from "@tanstack/react-router";

type NeuVectorCompatibilityChip = {
  label: string;
  to?: string;
};

type NeuVectorCompatibilityChipsProps = {
  items: NeuVectorCompatibilityChip[];
  testId?: string;
  /**
   * NeuVector mapping hints are migration material: they render only in the
   * migration surfaces (Settings › NeuVector migration, the switchboard),
   * never in primary product views (C1).
   */
  migration?: boolean;
};

export function NeuVectorCompatibilityChips({
  items,
  testId = "neuvector-compatibility",
  migration = false,
}: NeuVectorCompatibilityChipsProps) {
  if (!migration) return null;
  return (
    <section className="flex flex-wrap gap-2" data-testid={testId}>
      {items.map((item) => {
        const className = "inline-flex h-7 items-center rounded-full border border-border px-2.5 text-meta font-medium text-foreground";
        if (item.to) {
          return (
            <Link key={item.label} to="." href={item.to} className={`${className} hover:bg-accent`}>
              {item.label}
            </Link>
          );
        }
        return (
          <span key={item.label} className={className}>
            {item.label}
          </span>
        );
      })}
    </section>
  );
}
