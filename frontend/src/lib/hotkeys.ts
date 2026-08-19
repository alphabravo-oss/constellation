/**
 * Lightweight global hotkey manager — no deps.
 *
 * Supports:
 *   - single keys ("?", "Escape", "/")
 *   - meta/ctrl combos ("Mod+k")
 *   - vim-style chord prefixes ("g d", "g f")
 *
 * Mounts a single window-level keydown listener and dispatches to subscribers.
 * Skips events whose target is an editable surface (input/textarea/contenteditable)
 * unless the binding opts-in via `allowInEditable`.
 */
import { useEffect } from "react";

export interface Hotkey {
  combo: string;
  handler: (e: KeyboardEvent) => void;
  description?: string;
  allowInEditable?: boolean;
}

type Listener = Hotkey;

const listeners = new Set<Listener>();
let chordPrefix: string | null = null;
let chordTimer: number | null = null;

const isMac = typeof navigator !== "undefined" && /Mac|iPod|iPhone|iPad/.test(navigator.platform);

function isEditable(t: EventTarget | null): boolean {
  if (!(t instanceof HTMLElement)) return false;
  const tag = t.tagName;
  if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return true;
  if (t.isContentEditable) return true;
  return false;
}

function matchCombo(e: KeyboardEvent, combo: string): boolean {
  // combo: "Mod+k", "Shift+/", "Escape", "g d"
  const parts = combo.split("+").map((p) => p.trim());
  const key = parts[parts.length - 1];
  const mods = new Set(parts.slice(0, -1).map((m) => m.toLowerCase()));
  const wantMod = mods.has("mod");
  const wantCtrl = mods.has("ctrl");
  const wantShift = mods.has("shift");
  const wantAlt = mods.has("alt");
  const wantMeta = mods.has("meta");

  if (wantMod && !(isMac ? e.metaKey : e.ctrlKey)) return false;
  if (wantCtrl && !e.ctrlKey) return false;
  if (wantShift && !e.shiftKey) return false;
  if (wantAlt && !e.altKey) return false;
  if (wantMeta && !e.metaKey) return false;

  // For non-modified keys, require *no* modifiers (except shift for symbols)
  if (!wantMod && !wantCtrl && !wantAlt && !wantMeta) {
    if (e.metaKey || e.ctrlKey || e.altKey) return false;
  }

  const ek = e.key.length === 1 ? e.key.toLowerCase() : e.key;
  return ek === key.toLowerCase();
}

function dispatch(e: KeyboardEvent) {
  // Chord support — listener `combo` may be like "g d"
  const isPlainLetter = e.key.length === 1 && /^[a-zA-Z]$/.test(e.key) && !e.metaKey && !e.ctrlKey && !e.altKey;

  if (chordPrefix && isPlainLetter && !isEditable(e.target)) {
    const candidate = `${chordPrefix} ${e.key.toLowerCase()}`;
    for (const l of listeners) {
      if (l.combo.toLowerCase() === candidate) {
        e.preventDefault();
        l.handler(e);
        clearChord();
        return;
      }
    }
    clearChord();
  }

  for (const l of listeners) {
    if (isEditable(e.target) && !l.allowInEditable) continue;
    // Chord prefix init: listener whose combo starts with "g "
    if (l.combo.toLowerCase().startsWith(`${e.key.toLowerCase()} `) && isPlainLetter) {
      chordPrefix = e.key.toLowerCase();
      if (chordTimer) window.clearTimeout(chordTimer);
      chordTimer = window.setTimeout(clearChord, 1200);
      e.preventDefault();
      return;
    }
    if (!l.combo.includes(" ") && matchCombo(e, l.combo)) {
      l.handler(e);
    }
  }
}

function clearChord() {
  chordPrefix = null;
  if (chordTimer) { window.clearTimeout(chordTimer); chordTimer = null; }
}

let mounted = false;
function ensureListener() {
  if (mounted || typeof window === "undefined") return;
  window.addEventListener("keydown", dispatch);
  mounted = true;
}

export function registerHotkey(h: Hotkey): () => void {
  ensureListener();
  listeners.add(h);
  return () => { listeners.delete(h); };
}

export function useHotkey(combo: string, handler: (e: KeyboardEvent) => void, opts: { description?: string; allowInEditable?: boolean; enabled?: boolean } = {}) {
  useEffect(() => {
    if (opts.enabled === false) return;
    const off = registerHotkey({ combo, handler, description: opts.description, allowInEditable: opts.allowInEditable });
    return off;
  }, [combo, handler, opts.description, opts.allowInEditable, opts.enabled]);
}

export const HOTKEY_CATALOG: Array<{ combo: string; label: string; group: string }> = [
  { combo: "g d", label: "Go to Dashboard",   group: "Navigation" },
  { combo: "g f", label: "Go to Findings",    group: "Navigation" },
  { combo: "g h", label: "Go to Nodes",       group: "Navigation" },
  { combo: "g i", label: "Go to Images",      group: "Navigation" },
  { combo: "g a", label: "Go to Assets",      group: "Navigation" },
  { combo: "g c", label: "Go to Compliance",  group: "Navigation" },
  { combo: "g n", label: "Go to Network Map", group: "Navigation" },
  { combo: "g p", label: "Go to Policies",    group: "Navigation" },
  { combo: "g r", label: "Go to Runtime",     group: "Navigation" },
  { combo: "g v", label: "Go to CVE DB",      group: "Navigation" },
  { combo: "Mod+k", label: "Open Command Palette", group: "General" },
  { combo: "/",     label: "Focus search",         group: "General" },
  { combo: "?",     label: "Show keyboard help",   group: "General" },
  { combo: "Escape", label: "Close drawer / modal", group: "General" },
];

export function isMacOS(): boolean { return isMac; }
