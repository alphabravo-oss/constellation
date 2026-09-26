import { Eye, EyeOff } from "lucide-react";

import { Button } from "@/components/ui/button";

export function PlatformVisibilityToggle({
  hidden,
  onHiddenChange,
  hiddenCount,
  compact = false,
}: {
  hidden: boolean;
  onHiddenChange: (hidden: boolean) => void;
  hiddenCount?: number;
  compact?: boolean;
}) {
  const Icon = hidden ? EyeOff : Eye;
  const count = hidden && hiddenCount ? ` · ${hiddenCount}` : "";

  return (
    <Button
      type="button"
      size="sm"
      variant={hidden ? "secondary" : "outline"}
      onClick={() => onHiddenChange(!hidden)}
      aria-pressed={hidden}
      title="Hide Kubernetes, Constellation, and Astronomer platform components. Telemetry collection and protection stay active."
      data-testid="platform-visibility-toggle"
      className={compact ? "h-6 px-2 text-[11px] text-mono" : undefined}
    >
      <Icon className="h-3.5 w-3.5" aria-hidden />
      {hidden ? `Platform hidden${count}` : "Platform visible"}
    </Button>
  );
}
