/** Shared helpers for Hub-Securite modules. */
export function apiNs(ns) {
  const a = window.pywebview && window.pywebview.api;
  return a && a[ns];
}

export function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
