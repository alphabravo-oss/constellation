import { type ButtonHTMLAttributes, type ElementType, forwardRef } from "react";
import { Slot } from "radix-ui";
import { cn } from "@/lib/cn";
import { buttonBaseClass, buttonIntentClass, buttonSizeClass, type ButtonIntent, type ButtonSize } from "@/ui";

type Variant = "primary" | "secondary" | "ghost" | "outline" | "destructive" | "link";
type Size = "sm" | "md" | "lg" | "icon";

/**
 * Product button on the kit's intents. `primary` is the teal accent and is
 * reserved for the page's main action; everything else is the neutral bordered
 * default or ghost.
 */
const intent: Record<Variant, ButtonIntent> = {
  primary: "primary",
  secondary: "default",
  outline: "default",
  ghost: "ghost",
  destructive: "destructive",
  link: "link",
};
const size: Record<Size, ButtonSize> = { sm: "sm", md: "sm", lg: "md", icon: "icon" };

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  asChild?: boolean;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { className, variant = "secondary", size: sizeProp = "md", asChild, type, ...rest },
  ref,
) {
  const Comp: ElementType = asChild ? Slot.Root : "button";
  return (
    <Comp
      ref={ref}
      type={asChild ? undefined : (type ?? "button")}
      className={cn(buttonBaseClass, buttonIntentClass[intent[variant]], buttonSizeClass[size[sizeProp]], "[&_svg]:h-4 [&_svg]:w-4", className)}
      {...rest}
    />
  );
});
