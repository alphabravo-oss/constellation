import { useEffect, useRef, type ComponentRef } from "react";
import type { ErrorComponentProps } from "@tanstack/react-router";
import { ErrorState } from "@/ui";
import { correlationIdOf } from "@/components/ui/states";

/** A failed lazy import is cached by React; recovery needs a fresh document. */
export function RouteErrorPage({ error }: ErrorComponentProps) {
  const heading = useRef<ComponentRef<"h1">>(null);
  const message = error instanceof Error ? error.message : "";
  const moduleLoadFailed = /failed to fetch dynamically imported module|error loading dynamically imported module|importing a module script failed|loading (?:css )?chunk [\w-]+ failed|unable to preload css/i.test(message);
  useEffect(() => { heading.current?.focus(); }, []);

  return <section aria-labelledby="route-error-heading" data-testid="route-error">
    <h1 id="route-error-heading" ref={heading} tabIndex={-1} className="sr-only">This page could not be loaded</h1>
    <ErrorState
      title="This page could not be loaded"
      description={moduleLoadFailed
        ? "A console update or interrupted connection prevented this page from loading. Reload to try again."
        : "Something prevented this page from opening. Reload to try again, or return to clusters."}
      correlationId={correlationIdOf(error)}
      onRetry={() => window.location.reload()}
      retryLabel="Reload page"
    />
    <p className="-mt-10 text-center"><a href="/clusters" className="text-link text-sm">Return to clusters</a></p>
  </section>;
}
