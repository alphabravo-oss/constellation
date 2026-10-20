import {
  createContext,
  forwardRef,
  useContext,
  type AnchorHTMLAttributes,
  type ComponentType,
  type ReactNode,
} from "react";

/**
 * Everything product-specific the kit needs is injected here. The kit never
 * imports product code; Astronomer and Constellation each build one
 * `ProductConfig` and wrap their app in `ProductProvider`.
 */
export interface ProductLinkProps
  extends Omit<AnchorHTMLAttributes<HTMLAnchorElement>, "href"> {
  to: string;
  children?: ReactNode;
  /** Marks the link as the current page (sets aria-current when true). */
  current?: boolean;
}

export interface ProductConfig {
  /** Display name ("Astronomer", "Constellation"); operators may override. */
  name: string;
  /** Vendor shown in the footer ("AlphaBravo"). */
  vendor: string;
  /** Build/semantic version shown in the footer ("2.0.1"). */
  version: string;
  /** Square mark rendered at 28px in the sidebar brand row. */
  mark: ReactNode;
  /** Larger mark for the login hero (optional; falls back to `mark`). */
  markLarge?: ReactNode;
  /** Login hero texture: Astronomer owns "orbit", Constellation "starfield". */
  loginHero: "orbit" | "starfield";
  /** Documentation URL for the sidebar footer link. */
  docsUrl?: string;
  /** Router-aware link; defaults to a plain anchor. */
  Link: ComponentType<ProductLinkProps>;
}

const DefaultLink = forwardRef<HTMLAnchorElement, ProductLinkProps>(
  ({ to, current, children, ...rest }, ref) => (
    <a ref={ref} href={to} aria-current={current ? "page" : undefined} {...rest}>
      {children}
    </a>
  ),
);
DefaultLink.displayName = "DefaultLink";

const fallback: ProductConfig = {
  name: "Product",
  vendor: "AlphaBravo",
  version: "0.0.0",
  mark: null,
  loginHero: "orbit",
  Link: DefaultLink,
};

const ProductContext = createContext<ProductConfig>(fallback);

export function ProductProvider({
  config,
  children,
}: {
  config: ProductConfig;
  children: ReactNode;
}) {
  return (
    <ProductContext.Provider value={config}>{children}</ProductContext.Provider>
  );
}

export function useProduct(): ProductConfig {
  return useContext(ProductContext);
}

/**
 * Apply an operator branding color (hex) to the brand slots only. Everything
 * else in the system stays neutral by design (see docs/ui/KIT.md "Color").
 * Returns a restore function.
 */
export function applyBrandAccent(hex: string | null | undefined): () => void {
  const root = document.documentElement;
  const triplet = hex ? hexToHslTriplet(hex) : null;
  const slots = ["--brand", "--brand-from", "--brand-to"] as const;
  if (!triplet) return () => {};
  const previous = slots.map((slot) => root.style.getPropertyValue(slot));
  for (const slot of slots) root.style.setProperty(slot, triplet);
  return () => {
    slots.forEach((slot, index) => {
      if (previous[index]) root.style.setProperty(slot, previous[index]);
      else root.style.removeProperty(slot);
    });
  };
}

/** "#7c3aed" → "262 83% 58%" (HSL triplet without the hsl() wrapper). */
export function hexToHslTriplet(hex: string): string | null {
  const match = /^#?([0-9a-f]{6}|[0-9a-f]{3})$/i.exec(hex.trim());
  if (!match) return null;
  let value = match[1];
  if (value.length === 3)
    value = value
      .split("")
      .map((char) => char + char)
      .join("");
  const r = parseInt(value.slice(0, 2), 16) / 255;
  const g = parseInt(value.slice(2, 4), 16) / 255;
  const b = parseInt(value.slice(4, 6), 16) / 255;
  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  const l = (max + min) / 2;
  let h = 0;
  let s = 0;
  if (max !== min) {
    const d = max - min;
    s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
    switch (max) {
      case r:
        h = (g - b) / d + (g < b ? 6 : 0);
        break;
      case g:
        h = (b - r) / d + 2;
        break;
      default:
        h = (r - g) / d + 4;
    }
    h /= 6;
  }
  return `${Math.round(h * 360)} ${Math.round(s * 100)}% ${Math.round(l * 100)}%`;
}
