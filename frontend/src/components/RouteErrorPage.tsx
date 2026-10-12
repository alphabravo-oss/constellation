import { useEffect, useRef, type ComponentRef } from "react";
import type { ErrorComponentProps } from "@tanstack/react-router";
import { Button } from "@/components/ui/button";

/** A failed lazy import is cached by React; recovery needs a fresh document. */
export function RouteErrorPage({ error }: ErrorComponentProps) {
  const heading = useRef<ComponentRef<"h1">>(null);
  const message = error instanceof Error ? error.message : "";
  const moduleLoadFailed = /failed to fetch dynamically imported module|error loading dynamically imported module|importing a module script failed|loading (?:css )?chunk [\w-]+ failed|unable to preload css/i.test(message);
  useEffect(() => { heading.current?.focus(); }, []);

  return <section className="mx-auto max-w-xl space-y-4 p-8" aria-labelledby="route-error-heading">
    <h1 id="route-error-heading" ref={heading} tabIndex={-1} className="text-xl font-semibold">This page could not be loaded</h1>
    <p className="text-sm text-muted-foreground">{moduleLoadFailed
      ? "A console update or interrupted connection may have prevented this page from loading. Reload to try again."
      : "Something prevented this page from opening. Reload to try again, or return to Clusters."}</p>
    <div className="flex flex-wrap items-center gap-3">
      <Button onClick={() => window.location.reload()}>Reload page</Button>
      <a href="/clusters" className="text-sm text-primary underline underline-offset-2">Return to Clusters</a>
    </div>
  </section>;
}
