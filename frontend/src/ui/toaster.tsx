import { Toaster } from "sonner";
import { useTheme } from "./theme";

/** One toast placement for both products: bottom-right, 4 s, themed. */
export function KitToaster() {
  const { resolved } = useTheme();
  return (
    <Toaster
      position="bottom-right"
      theme={resolved}
      richColors
      closeButton
      toastOptions={{ className: "border border-border", duration: 4000 }}
    />
  );
}
