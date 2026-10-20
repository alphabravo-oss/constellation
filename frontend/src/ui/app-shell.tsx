import { type ReactNode, type Ref } from "react";
import { WifiOff } from "lucide-react";
import { cn } from "./cn";
import { useProduct } from "./product";

export type ContentLayout = "contained" | "full-bleed";

/**
 * The application frame: sidebar (240 / 64 px rail) on the left, a 56 px
 * header, optional banners, the `<main>` region with a skip-link target, and
 * the product footer inside the sidebar. `contentLayout` decides between the
 * contained max-width (pages) and full-bleed (dense tables, logs, graphs).
 */
export function AppShell({
  sidebar,
  header,
  banners,
  offline = false,
  contentLayout = "contained",
  mainRef,
  children,
  overlays,
  testId = "app-shell",
}: {
  sidebar: ReactNode;
  header: ReactNode;
  banners?: ReactNode;
  offline?: boolean;
  contentLayout?: ContentLayout;
  mainRef?: Ref<HTMLElement>;
  children: ReactNode;
  /** Portals and global overlays (palette, drawers, window manager). */
  overlays?: ReactNode;
  testId?: string;
}) {
  return (
    <div
      data-testid={testId}
      className="flex h-screen overflow-hidden bg-background"
    >
      <a
        href="#main"
        className="sr-only fixed left-3 top-3 z-toast rounded-md bg-background px-3 py-2 text-sm font-medium text-foreground shadow-elev-3 focus:not-sr-only"
      >
        Skip to main content
      </a>
      {sidebar}
      <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
        {header}
        {banners}
        {offline ? <OfflineBanner /> : null}
        <main
          id="main"
          ref={mainRef}
          tabIndex={-1}
          className="min-h-0 flex-1 overflow-y-auto outline-hidden"
        >
          <div
            data-content-layout={contentLayout}
            className={cn(
              "mx-auto w-full animate-fade-in px-4 py-6 sm:px-(--content-gutter)",
              contentLayout === "contained" && "max-w-(--content-max)",
            )}
          >
            {children}
          </div>
        </main>
      </div>
      {overlays}
    </div>
  );
}

export function OfflineBanner() {
  return (
    <div
      role="status"
      className="flex items-center gap-2 border-b border-status-warning/30 bg-status-warning/15 px-4 py-2 text-sm text-status-warning"
    >
      <WifiOff className="h-4 w-4 shrink-0" />
      You are offline. Live updates and changes will fail until connectivity
      returns.
    </div>
  );
}

/** "Product x.y.z · Vendor" — one spelling in both products. */
export function ProductFooter({ className }: { className?: string }) {
  const product = useProduct();
  return (
    <p className={cn("text-micro text-muted-foreground", className)}>
      {product.name} {product.version} · {product.vendor}
    </p>
  );
}
