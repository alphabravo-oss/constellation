import { type ClassValue, clsx } from "clsx";
import { extendTailwindMerge } from "tailwind-merge";

// The kit's semantic font-size tokens (tokens.css @theme) are sizes, not
// colors; teach tailwind-merge so `text-meta text-foreground` keeps both.
const twMerge = extendTailwindMerge({
  extend: {
    classGroups: {
      "font-size": [
        {
          text: [
            "2xs",
            "body",
            "meta",
            "micro",
            "page-title",
            "section-title",
            "section-title-lg",
            "stat",
            "9",
            "10",
            "11",
            "13",
          ],
        },
      ],
    },
  },
});

/** Merge Tailwind class lists with conflict resolution. */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}
