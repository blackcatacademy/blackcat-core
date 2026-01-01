# Legacy front controller references

This folder contains **legacy** front controller files copied from older BlackCat apps (e.g. eshop prototypes).

Important:
- These files are **not** part of the supported `blackcat-core` public API.
- They are **app-specific** and may reference paths/files that do not exist in `blackcat-core`.
- Do **not** treat them as secure by default; prefer the supported hardened templates:
  - `blackcat-core/templates/http/index.php`
  - `blackcat-core/templates/http/.htaccess`

Files:
- `eshop-index.php` — historical eshop-style router/front controller (reference only).

