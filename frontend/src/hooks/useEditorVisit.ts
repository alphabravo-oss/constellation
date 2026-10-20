import { useEffect, useRef } from "react";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";

/** Completion effects belong to one mounted editor visit, not a reusable URL. */
export function useEditorVisit(target: readonly unknown[]) {
  const owner = useTablePreferencesIdentity();
  const context = JSON.stringify([owner?.org_id, owner?.user_id, ...target]);
  const current = useRef({ context });
  if (current.current.context !== context) current.current = { context };
  const visit = current.current;
  const mounted = useRef(false);
  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; };
  }, []);
  return { visit, isCurrent: () => mounted.current && current.current === visit };
}
