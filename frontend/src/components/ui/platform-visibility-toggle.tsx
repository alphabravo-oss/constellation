/**
 * Retired (C1): platform visibility is the header "System workloads" scope
 * switch, which drives usePlatformComponentVisibility for every inventory.
 * Kept as a no-op so callers outside the inventory pages keep compiling.
 */
export function PlatformVisibilityToggle(_props: {
  hidden: boolean;
  onHiddenChange: (hidden: boolean) => void;
  hiddenCount?: number;
  compact?: boolean;
}) {
  return null;
}
