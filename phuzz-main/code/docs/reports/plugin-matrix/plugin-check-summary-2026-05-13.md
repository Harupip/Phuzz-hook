# Tom tat plugin thu nghiem ngay 2026-05-13

Trong workspace hien tai, plugin duoc thu nghiem co artifact ro rang trong ngay `2026-05-13` la `photo-gallery` va `show-all-comments-in-one-page`.

## Ket qua

- `photo-gallery` (`SQLi`): `success`
  - WordPress kich hoat plugin thanh cong
  - `FUZZER_CONFIG=wordpress/photo-gallery`
  - PHUZZ ghi nhan `33` request trace lines
  - ZIP duoc tai trong luc chay: `photo-gallery.zip`
- `show-all-comments-in-one-page` (`XSS` target): `no vuln found in two 30-minute reruns`
  - mode `2` (hook-aware): khong tao `vulnerable-candidates.json`, co `472` file `error-*.json`
  - mode `1` (PHUZZ goc): khong tao `vulnerable-candidates.json`, co `475` file `error-*.json`
  - log mode `1` chay toi khoang `req 477`

## Ket luan nhanh

Buoi thu nghiem ngay `2026-05-13` cho thay:

- pipeline WordPress + PHUZZ van chay on voi `photo-gallery`
- `show-all-comments-in-one-page` chay duoc o ca `mode 1` va `mode 2`, nhung hai lan rerun 30 phut deu chua tai hien vuln

## Nguon

- `code/docs/reports/plugin-matrix/photo-gallery-smoke-2026-05-13.md`
- `code/docs/reports/plugin-matrix/photo-gallery-smoke-2026-05-13.json`
- `code/fuzzer/output/benchmarks/manual-reruns/comparison-ready-summary.json`
- `code/fuzzer/output/benchmarks/manual-reruns/20260513-131027-mode2-baseline-no-vul/`
- `code/fuzzer/output/benchmarks/manual-reruns/20260513-134409-mode1-rerun-no-vul/`
