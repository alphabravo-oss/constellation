/**
 * Render a hotkey combo as a list of human-friendly tokens
 * (handles "Mod+k" → ["⌘", "K"] on mac, ["Ctrl", "K"] otherwise).
 */
import { isMacOS } from "./hotkeys";

export function tokenize(combo: string): string[] {
  if (combo.includes(" ")) {
    // chord: "g d" → ["g", "then", "d"] visually, but we just split.
    return combo.split(" ");
  }
  const mac = isMacOS();
  return combo.split("+").map((part) => {
    const p = part.trim();
    const lower = p.toLowerCase();
    if (lower === "mod") return mac ? "⌘" : "Ctrl";
    if (lower === "shift") return mac ? "⇧" : "Shift";
    if (lower === "alt") return mac ? "⌥" : "Alt";
    if (lower === "ctrl") return mac ? "⌃" : "Ctrl";
    if (lower === "meta") return mac ? "⌘" : "Win";
    if (lower === "enter") return "↵";
    if (lower === "escape") return "Esc";
    if (lower === "arrowup") return "↑";
    if (lower === "arrowdown") return "↓";
    if (p.length === 1) return p.toUpperCase();
    return p;
  });
}
