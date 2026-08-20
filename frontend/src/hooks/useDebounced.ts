import { useEffect, useState } from "react";

// useDebounced returns a value that only updates after `ms` of no changes — keeps
// server-side search from firing a request on every keystroke.
export function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}
