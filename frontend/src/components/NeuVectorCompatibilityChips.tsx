import { Link } from "react-router-dom";

type NeuVectorCompatibilityChip = {
  label: string;
  to?: string;
};

type NeuVectorCompatibilityChipsProps = {
  items: NeuVectorCompatibilityChip[];
  testId?: string;
};

export function NeuVectorCompatibilityChips({
  items,
  testId = "neuvector-compatibility",
}: NeuVectorCompatibilityChipsProps) {
  return (
    <section className="flex flex-wrap gap-2" data-testid={testId}>
      {items.map((item) => {
        const className = "rounded-md border border-primary/20 bg-primary/5 px-2.5 py-1 text-xs font-medium text-primary";
        if (item.to) {
          return (
            <Link key={item.label} to={item.to} className={`${className} hover:border-primary/40 hover:bg-primary/10`}>
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
