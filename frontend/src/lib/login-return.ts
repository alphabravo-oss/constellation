export function loginReturnPath(raw: string | null): string {
  const fallback = "/clusters";
  if (!raw?.startsWith("/") || raw.startsWith("//") || raw.includes("\\")) return fallback;
  try {
    const url = new URL(raw, "https://constellation.invalid");
    return url.origin === "https://constellation.invalid" ? `${url.pathname}${url.search}${url.hash}` : fallback;
  } catch {
    return fallback;
  }
}
