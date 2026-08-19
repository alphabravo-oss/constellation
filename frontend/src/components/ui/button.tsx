import { type ButtonHTMLAttributes, type ElementType, forwardRef } from "react";
import { Slot } from "@radix-ui/react-slot";
import { cn } from "@/lib/cn";

type Variant = "primary" | "secondary" | "ghost" | "outline" | "destructive";
type Size = "sm" | "md" | "lg" | "icon";

const variantClass: Record<Variant, string> = {
  primary:    "bg-primary text-primary-foreground hover:bg-[color-mix(in_oklab,var(--color-primary)_88%,white)] shadow-[var(--elev-1)]",
  secondary:  "bg-secondary text-secondary-foreground hover:bg-[color-mix(in_oklab,var(--color-secondary)_92%,var(--color-foreground))]",
  ghost:      "hover:bg-accent text-foreground",
  outline:    "border border-border bg-transparent text-foreground hover:bg-accent",
  destructive:"bg-destructive text-destructive-foreground hover:bg-[color-mix(in_oklab,var(--color-destructive)_88%,white)]",
};

const sizeClass: Record<Size, string> = {
  sm:   "h-7 px-2.5 text-xs gap-1.5 rounded",
  md:   "h-8 px-3 text-sm gap-2 rounded-md",
  lg:   "h-9 px-4 text-sm gap-2 rounded-md",
  icon: "h-7 w-7 rounded",
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  asChild?: boolean;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { className, variant = "secondary", size = "md", asChild, ...rest },
  ref,
) {
  const Comp: ElementType = asChild ? Slot : "button";
  return (
    <Comp
      ref={ref}
      className={cn(
        "inline-flex items-center justify-center whitespace-nowrap font-medium transition-colors duration-100 disabled:pointer-events-none disabled:opacity-50",
        variantClass[variant],
        sizeClass[size],
        className,
      )}
      {...rest}
    />
  );
});
