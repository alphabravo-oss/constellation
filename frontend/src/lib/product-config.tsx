import { forwardRef, useMemo, type ReactNode } from "react";
import { Link as RouterLink } from "@tanstack/react-router";
import { ProductProvider, type ProductConfig, type ProductLinkProps } from "@/ui";
import { cn } from "@/lib/cn";
import { BUILD_INFO } from "@/lib/build-info";

/** Footer version: the stamped release, or the package version in dev builds. */
export const APP_VERSION = BUILD_INFO.version && BUILD_INFO.version !== "dev" ? BUILD_INFO.version : "0.3.0";

/** Router-aware link handed to the shared kit (string hrefs, no typed routes). */
const ConstellationLink = forwardRef<HTMLAnchorElement, ProductLinkProps>(
  ({ to, current, children, className, ...rest }, ref) => (
    <RouterLink
      ref={ref}
      to="."
      href={to}
      activeOptions={{ exact: true }}
      activeProps={{}}
      aria-current={current ? "page" : undefined}
      className={className}
      {...rest}
    >
      {children}
    </RouterLink>
  ),
);
ConstellationLink.displayName = "ConstellationLink";

/**
 * Constellation's mark: the line-art constellation (hub star joined to three
 * others) in white on the teal brand gradient. Same tile geometry as
 * Astronomer's Orbit mark so the two products read as siblings.
 */
export function ConstellationMark({
  size = "sm",
  className,
}: {
  size?: "sm" | "lg";
  className?: string;
}) {
  const dimension = size === "lg" ? "h-10 w-10 rounded-xl" : "h-7 w-7 rounded-lg";
  return (
    <span
      aria-hidden="true"
      data-testid="constellation-mark"
      className={cn(
        dimension,
        "flex items-center justify-center bg-linear-to-br from-brand-from to-brand-to text-white",
        className,
      )}
    >
      <svg
        viewBox="0 0 24 24"
        className={size === "lg" ? "h-6 w-6" : "h-[18px] w-[18px]"}
        fill="none"
        stroke="currentColor"
        strokeWidth={1.75}
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <line x1="5.6" y1="5.9" x2="10.9" y2="9.1" />
        <line x1="19.5" y1="5.3" x2="14.1" y2="9.0" />
        <line x1="11.9" y1="12.2" x2="9.8" y2="17.6" />
        <circle cx="4" cy="5" r="1.9" />
        <circle cx="12.5" cy="10.1" r="1.9" />
        <circle cx="21" cy="4.2" r="1.9" />
        <circle cx="9.1" cy="19.6" r="1.9" />
      </svg>
    </span>
  );
}

export function ConstellationProductProvider({ children }: { children: ReactNode }) {
  const config = useMemo<ProductConfig>(
    () => ({
      name: "Constellation",
      vendor: "AlphaBravo",
      version: APP_VERSION,
      mark: <ConstellationMark />,
      markLarge: <ConstellationMark size="lg" />,
      loginHero: "starfield",
      Link: ConstellationLink,
    }),
    [],
  );
  return <ProductProvider config={config}>{children}</ProductProvider>;
}
