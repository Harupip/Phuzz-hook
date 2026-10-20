# Chạy WordPress trên nhánh online-linked

Cập nhật **2026-10-09**, theo working tree gồm WIP batch/ZIP folder. Workflow WordPress duy nhất: `online-linked`, Zend và CMPLOG được runner bật. Không cần manual config cùng slug plugin.

## Chuẩn bị

Từ `phuzz-main/code`, cần PowerShell 7 (`pwsh`), Python có dependencies trong `fuzzer/requirements.txt`, Docker Desktop/Compose, `web/applications/wordpress/wp-cli.phar`, bootstrap config `fuzzer/configs/wordpress/bootstrap-generated.json` và ZIP `<slug>.zip`.

`PLUGIN_ZIP_DIR` trong [phuzz.env](../../phuzz.env) nhận path tuyệt đối hoặc tương đối với `phuzz-main/code`. Chọn ZIP theo thứ tự:

1. `PLUGIN_ZIP_DIR/<slug>.zip` nếu tồn tại.
2. `web/applications/wordpress/_plugins/<slug>.zip`.

Thư mục ưu tiên được mount read-only vào `/plugin-zips`; install recipe áp dụng fallback tương tự cho dependency ZIP. Dependency tự cài hiện có: WooCommerce cho `udraw`, Contact Form 7 cho `country-state-city-auto-dropdown`. Plugin khác có thể cần dependency/data riêng trước khi callback đăng ký. ZIP được staging không chứng minh plugin đã active hay endpoint đã chạy.

Tên ZIP bỏ `.zip` chính là slug runner; không tự bỏ prefix priority hay version. Ví dụ `300000-imsanity.2.8.2.zip` không tương đương `imsanity.zip`. Chọn archive đúng slug và đúng version cần tái hiện. `-ForcePlugins` chỉ áp dụng download script plugin mặc định `show-all-comments-in-one-page`.

## Một plugin

```powershell
pwsh -NoProfile -File ./phuzz.ps1 -PluginSlug imsanity -DryRun
pwsh -NoProfile -NonInteractive -File ./phuzz.ps1 -PluginSlug imsanity
# Override ngân sách ban đầu, không sửa phuzz.env
pwsh -NoProfile -NonInteractive -File ./phuzz.ps1 -PluginSlug imsanity -OnlineTimeoutSeconds 60 -OnlineMaxVersions 3 -OnlineMaxCandidates 32 -OnlineCampaignTimeoutSeconds 3600
```

Không tham số: wrapper có menu local plugin từ cả thư mục ưu tiên và `_plugins`, dedupe theo slug. Có `-PluginSlug` hoặc `-DryRun`: không hỏi chọn plugin; `-DryRun` không có slug dùng plugin mặc định. Dry-run chưa kiểm tra archive/config/Docker readiness.

## Batch ZIP tuần tự

```powershell
pwsh -NoProfile -File ./phuzz.ps1 -AllPlugins -DryRun
pwsh -NoProfile -NonInteractive -File ./phuzz.ps1 -AllPlugins
```

Batch lấy **file ZIP trực tiếp** trong `PLUGIN_ZIP_DIR`; nếu setting trống thì lấy `_plugins`. Không gộp cả hai folder, không recurse, không nhận directory tên `.zip`. Sắp theo filename, chạy từng plugin, tiếp tục sau runner exception/nonzero exit; cuối batch trả 1 nếu có run lỗi, 0 nếu không. Không kết hợp `-AllPlugins` với `-PluginSlug`. Folder thiếu/rỗng báo lỗi trước run.

Mỗi plugin có run ID, campaign budget và artifacts riêng. Batch tắt comparison prompt bằng `-NoComparePrompt`; không có resume batch ZIP trong wrapper. Runner completed/exit 0 có thể vẫn chứa candidate `PARTIAL` hoặc `NOT_VERIFIED`.

## Settings và chạy không tương tác

Ưu tiên CLI > `phuzz.env` > loader defaults. Snapshot file ngày 2026-10-09: `ONLINE_TIMEOUT_SECONDS=30`, `ONLINE_MAX_VERSIONS=9`, `ONLINE_MAX_CANDIDATES=32`, `ONLINE_CAMPAIGN_TIMEOUT_SECONDS=3600`; defaults loader khác file. Các giá trị này là **initial budget**, có thể tăng khi có progress đã xác minh tới hard cap. Xem [budget/resume](online-linked-flow.md#initial-budget-và-hard-cap).

`ONLINE_COMPARE_PROMPT=1` hỏi so sánh khi single-plugin run kết thúc, terminal tương tác và có final export. Chạy `-NonInteractive` hoặc đặt setting `0` để batch tooling không đợi trả lời. `-NoFollowLogs` giữ tương thích, không vô hiệu prompt này. `-StopOnVulnCount 0` chỉ tắt dừng theo số finding.

Bootstrap/build/cleanup có thời gian riêng, ngoài campaign budget; hard campaign cap mặc định có thể lên 86400s. Khi chạy bằng automation, đặt outer process timeout theo hard cap cộng phần bootstrap/cleanup và tổng số plugin. Không coi initial `3600` là wall-clock trần toàn lệnh. Không tăng budget để bỏ qua replay/provenance failure.

## Đọc kết quả và debug

Mở `fuzzer/output/online-linked/<run-id>/batch-state.json`, lấy `state_path` của candidate. Đọc `readiness`/`replay_result`, Pass 2, worker status và terminal reason riêng; rồi xem `final-config-summary.json` → `exported_configs`. Final files active nằm ở `final-configs/*.json`, bản được thay thế ở `final-configs/superseded/`.

`fuzzer/output/workers/fuzzer-N` là output worker, không thay candidate state; fuzzer xóa output của cùng node ID khi khởi động lại. Snapshot/evidence campaign mới là nơi đối chiếu provenance. PowerShell runner reset artifact runtime trong shared volume trước campaign; Bash wrapper còn xóa `fuzzer/output`, nên dùng PowerShell để giữ host run history.

```powershell
docker compose logs --tail=100 web
docker compose ps
```

Không gọi lại wrapper để resume cùng run: nó tạo run ID mới. Python coordinator có `--resume` với input/Compose/budget context cũ; xem [checkpoint/resume](online-linked-flow.md#checkpoint-và-resume). HTTP 200, file count hoặc exit 0 chưa chứng minh fuzzing PASS.

## Hướng dẫn matrix lịch sử

Phần dưới lưu workflow/config matrix tháng 05-2026. Danh sách plugin và kết quả validate là snapshot cũ, không phải acceptance hiện tại của online-linked. Dùng lệnh phuzz.ps1 bên trên cho workflow hiện hành; không diễn giải matrix PASS thành runtime discovery PASS.

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
