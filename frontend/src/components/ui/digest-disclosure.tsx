/** Digests stay available for exact identity checks without dominating the view. */
export function DigestDisclosure({ digest }: { digest?: string }) {
  if (!digest) return null;
  return <details className="mt-1 min-w-0 text-xs text-muted-foreground" key={digest}>
    <summary className="w-fit cursor-pointer hover:text-foreground">Show digest</summary>
    <code className="mt-1 block break-all select-text">{digest}</code>
  </details>;
}
