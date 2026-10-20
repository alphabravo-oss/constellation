/**
 * API error envelope (Phase 1): `{"error": {"code", "message", "request_id"}}`
 * with `X-Request-ID` CORS-exposed on every response. The legacy shapes
 * (`{"error": "text"}`, `{"message": "text"}`, top-level `code`) are still
 * read so mixed-version backends keep producing useful messages.
 */
interface ErrorEnvelope { error?: unknown; message?: unknown; code?: unknown; request_id?: unknown }
interface MaybeAxios { response?: { status?: number; data?: unknown; headers?: Record<string, unknown> }; message?: unknown }

function body(error: unknown): ErrorEnvelope | undefined {
  const data = (error as MaybeAxios | null | undefined)?.response?.data;
  return data && typeof data === "object" ? (data as ErrorEnvelope) : undefined;
}

function nested(error: unknown): { code?: unknown; message?: unknown; request_id?: unknown } | undefined {
  const value = body(error)?.error;
  return value && typeof value === "object" ? (value as { code?: unknown; message?: unknown; request_id?: unknown }) : undefined;
}

/** Server-provided message (new or legacy shape), or undefined. */
export function apiErrorMessage(error: unknown): string | undefined {
  const data = body(error);
  const candidates = [nested(error)?.message, typeof data?.error === "string" ? data.error : undefined, data?.message];
  const found = candidates.find((value): value is string => typeof value === "string" && value.trim() !== "");
  if (found) return found;
  const raw = (error as MaybeAxios | null | undefined)?.response?.data;
  return typeof raw === "string" && raw.trim() && !raw.trim().startsWith("<") ? raw.trim() : undefined;
}

/** Machine-readable error code (new or legacy shape). */
export function apiErrorCode(error: unknown): string | undefined {
  const code = nested(error)?.code ?? body(error)?.code;
  return typeof code === "string" ? code : undefined;
}

/** Request correlation id: body `error.request_id`, then the X-Request-ID header. */
export function apiRequestId(error: unknown): string | null {
  const fromBody = nested(error)?.request_id ?? body(error)?.request_id;
  if (typeof fromBody === "string" && fromBody) return fromBody;
  const headers = (error as MaybeAxios | null | undefined)?.response?.headers;
  const header = headers?.["x-request-id"] ?? headers?.["X-Request-ID"];
  return typeof header === "string" && header ? header : null;
}

/** Message for display: server message, then the client error message, then `fallback`. */
export function apiErrorText(error: unknown, fallback: string): string {
  return apiErrorMessage(error) ?? (error instanceof Error && error.message ? error.message : fallback);
}
