// Apply the stored theme before first paint. External same-origin script so
// the CSP never needs 'unsafe-inline'. Keep the key in sync with
// src/contexts/ThemeContext.tsx (THEME_STORAGE_KEY).
(function () {
  try {
    var theme = localStorage.getItem("constellation.theme");
    var dark =
      theme === "light"
        ? false
        : theme === "dark"
          ? true
          : window.matchMedia("(prefers-color-scheme: dark)").matches;
    document.documentElement.classList.toggle("dark", dark);
    document.documentElement.style.colorScheme = dark ? "dark" : "light";
  } catch (_error) {
    document.documentElement.classList.add("dark");
  }
})();
