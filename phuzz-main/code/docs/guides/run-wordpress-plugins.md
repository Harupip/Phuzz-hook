# Cach chay WordPress PHUZZ voi tung plugin

Tai lieu nay dung cho repo:

`phuzz-main\code`

## 1. Vao dung thu muc

Mo PowerShell va chay:

```powershell
cd phuzz-main\code
```

Tat ca cac lenh ben duoi deu chay tu thu muc nay.

Với `phuzz.ps1 -Mode online-linked -UseZendDiscovery`, xem [luồng online-linked](online-linked-flow.md): lệnh chạy, ngân sách từng candidate, replay/Pass 2, vị trí state và những phần còn thiếu của vòng khám phá online.

## 2. Chay plugin mac dinh

Plugin mac dinh hien tai la:

```text
show-all-comments-in-one-page
```

Chay:

```powershell
.\run-wordpress-phuzz.ps1 -NoFollowLogs
```

Neu muon xem log fuzzer sau khi da start:

```powershell
docker compose logs -f fuzzer-wordpress-plugin
```

Lenh nay chi nen dung cho plugin mac dinh. Neu muon doi plugin, dung runner o muc tiep theo.

## 3. Chay 1 plugin khac

Dung `run-wordpress-plugin-matrix.ps1` va truyen slug plugin vao `-Plugins`.

Vi du chay `photo-gallery`:

```powershell
.\run-wordpress-plugin-matrix.ps1 -DownloadMissing -Plugins photo-gallery
```

Vi du chay `seo-local-rank`:

```powershell
.\run-wordpress-plugin-matrix.ps1 -DownloadMissing -Plugins seo-local-rank
```

Vi du chay `nirweb-support`:

```powershell
.\run-wordpress-plugin-matrix.ps1 -DownloadMissing -Plugins nirweb-support
```

Moi lan doi plugin, chi can doi slug sau `-Plugins`.

## 4. Chay nhieu plugin lan luot

Truyen nhieu slug vao `-Plugins`, cach nhau bang dau phay:

```powershell
.\run-wordpress-plugin-matrix.ps1 -DownloadMissing -Plugins photo-gallery,seo-local-rank,nirweb-support
```

Runner se chay tung plugin mot. Voi moi plugin, no se:

- kiem tra config PHUZZ tai `fuzzer/configs/wordpress/<plugin>.json`
- kiem tra hoac tai ZIP plugin vao `web/applications/wordpress/_plugins/`
- tao Docker override tam thoi de doi plugin
- restart WordPress va fuzzer cho plugin do
- kiem tra plugin da active trong WordPress
- kiem tra `FUZZER_CONFIG=wordpress/<plugin>`
- doc log de xac nhan PHUZZ co gui request

## 5. Chay tat ca plugin

Chay toan bo matrix:

```powershell
.\run-wordpress-plugin-matrix.ps1 -DownloadMissing
```

Neu bi dung giua chung va muon chay tiep dua tren file JSON report cu:

```powershell
.\run-wordpress-plugin-matrix.ps1 -DownloadMissing -Resume -JsonReportPath .\docs\reports\plugin-matrix\<ten-report>.json
```

Thay `<ten-report>.json` bang file report thuc te trong `docs\reports\plugin-matrix`.

## 6. Tai lai ZIP plugin

Binh thuong chi can `-DownloadMissing`. Neu muon tai lai ZIP du da ton tai:

```powershell
.\run-wordpress-plugin-matrix.ps1 -DownloadMissing -ForceDownload -Plugins photo-gallery
```

## 7. Noi xem ket qua

Sau moi lan chay, runner se sinh report trong:

```text
docs\reports\plugin-matrix\
```

Vi du:

```text
docs\reports\plugin-matrix\wordpress-plugin-matrix-2026-05-12.md
docs\reports\plugin-matrix\wordpress-plugin-matrix-2026-05-12.json
```

Doc tong hop target hien co:

```text
docs\reference\wordpress-plugin-targets.md
```

Neu can xem log Docker truc tiep:

```powershell
docker compose logs --tail=200 web
docker compose logs --tail=200 fuzzer-wordpress-plugin
```

Neu muon follow log fuzzer:

```powershell
docker compose logs -f fuzzer-wordpress-plugin
```

## 8. Danh sach plugin da validate thanh cong

Theo report ngay 2026-05-12, cac plugin sau da chay thanh cong:

```text
nirweb-support
arprice-responsive-pricing-table
ubigeo-peru
photo-gallery
show-all-comments-in-one-page
essential-real-estate
crm-perks-forms
rezgo
gallery-album
usc-e-shop
udraw
seo-local-rank
hypercomments
nmedia-user-file-uploader
joomsport-sports-league-results-management
totop-link
webp-converter-for-media
phastpress
```

Vi du lenh chay nhanh voi mot plugin trong danh sach:

```powershell
.\run-wordpress-plugin-matrix.ps1 -DownloadMissing -Plugins gallery-album
```

## 9. Plugin tung fail trong lan validate gan nhat

Theo report ngay 2026-05-12, cac plugin sau chua pass matrix:

```text
kivicare-clinic-management-system
newsletter-optin-box
all-in-one-wp-security-and-firewall
pie-register
```

Ly do trong report gan nhat:

- `kivicare-clinic-management-system`: timeout khi doi `http://localhost:8080/`
- `newsletter-optin-box`: plugin khong active sau WordPress bootstrap
- `all-in-one-wp-security-and-firewall`: khong doc duoc active plugins
- `pie-register`: khong doc duoc active plugins

Khi demo hoac benchmark nhanh, nen uu tien cac plugin trong muc "da validate thanh cong".

## 10. Cac slug hop le

Tat ca slug co config PHUZZ trong repo:

```text
all-in-one-wp-security-and-firewall
arprice-responsive-pricing-table
crm-perks-forms
essential-real-estate
gallery-album
hypercomments
joomsport-sports-league-results-management
kivicare-clinic-management-system
newsletter-optin-box
nirweb-support
nmedia-user-file-uploader
phastpress
photo-gallery
pie-register
rezgo
seo-local-rank
show-all-comments-in-one-page
totop-link
ubigeo-peru
udraw
usc-e-shop
webp-converter-for-media
```

## 11. Tom tat cach nho nhanh

Mac dinh:

```powershell
.\run-wordpress-phuzz.ps1 -NoFollowLogs
```

Doi sang plugin bat ky:

```powershell
.\run-wordpress-plugin-matrix.ps1 -DownloadMissing -Plugins <plugin-slug>
```

Chay nhieu plugin:

```powershell
.\run-wordpress-plugin-matrix.ps1 -DownloadMissing -Plugins <plugin-1>,<plugin-2>,<plugin-3>
```

Chay tat ca plugin:

```powershell
.\run-wordpress-plugin-matrix.ps1 -DownloadMissing
```
