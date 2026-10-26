# Rút gọn request artifact — 2026-10-26

Bắt đầu 2026-10-26; chốt kiểm chứng và tài liệu 2026-10-27 (Asia/Saigon).

## Mục tiêu và quyết định

Người dùng ưu tiên kết quả discovery và yêu cầu ghi lại thay đổi để điều tra về sau. Chọn cách ít ảnh hưởng: ghi JSON gọn và bỏ **bản sao metadata blindspot** trong mỗi request. Không chuyển sang registry dùng chung giữa các request, không giảm số opcode event, không cắt input, không đổi scoring hay điều kiện replay/Pass 2. Không xóa hay sửa artifact lịch sử.

## Đã thay đổi gì

| Thành phần | Thay đổi |
| --- | --- |
| PHP `uopz_hook_wp.php` | Request mới mang `schema_version=uopz-request-v4`. Giữ nguyên toàn bộ `registered_callbacks`, `executed_callbacks`, input/response, ID tương quan và metadata parent/child/REST. Không chép thêm map `hook_coverage.blindspot_callbacks`; giữ `blindspot_callback_ids` và số lượng trong summary. |
| `seed_validator.request_blindspot_callbacks(payload)` | Đọc map đầy đủ của v3; với v4, tra từng blindspot ID trong `registered_callbacks` **của cùng request**. Thiếu ID hoặc tham chiếu sai phải báo lỗi, không tự đoán. |
| Bootstrap fallback registry | Dùng helper trên rồi giữ nguyên bước chuẩn hóa callback ID cũ, kể cả map có alias hoặc descriptor thiếu trường `callback_id`. |
| PHP atomic JSON writer | Bỏ thụt lề/xuống dòng; kiểm tra mã hóa, số byte ghi và rename. Không công bố file rỗng/hỏng khi ghi thất bại; giữ destination cũ và bỏ file tạm lỗi. Aggregate coverage vẫn giữ đầy đủ các map, chỉ thay cách định dạng JSON. |
| Replay artifact loader | JSON hỏng trả lỗi kèm đường dẫn, số byte và nguyên nhân, thay vì chỉ hiện `Expecting value`. |

Metadata blindspot được khôi phục bằng ID, không suy ra bằng phép trừ tùy ý: callback inactive không tự trở thành blindspot. Registered/executed descriptors và Zend artifact không bị rút bớt trường.

## Nhận dạng lỗi để điều tra

- `HOOKPHUZZ_ARTIFACT_JSON_ENCODE_FAILED path=... reason=...`: PHP không mã hóa được dữ liệu; xem stderr/Apache error log. Không thay dữ liệu lỗi bằng dữ liệu giả hợp lệ.
- `HOOKPHUZZ_ARTIFACT_WRITE_FAILED path=... expected_bytes=... written_bytes=... reason=...`: ghi thiếu byte hoặc không ghi được, ví dụ hết chỗ.
- `HOOKPHUZZ_ARTIFACT_RENAME_FAILED path=... reason=...`: không công bố được file hoàn tất.
- `REQUEST_JSON_INVALID path=... bytes=... reason=...`: runner đọc phải JSON không hợp lệ; đường dẫn được giữ trong lý do gate thất bại.
- `REQUEST_BLINDSPOT_IDS_INVALID request_id=...` hoặc `REQUEST_BLINDSPOT_REFERENCE_MISSING request_id=... callback_id=...`: v4 thiếu danh sách ID hoặc trỏ tới callback không có trong chính request.

Các lỗi này không tự thành PASS. Thay đổi này chưa gộp lỗi lặp trên console, chưa thêm cleanup/rotation và chưa sửa lỗi khóa checkpoint Windows.

## Số đo và kiểm chứng

Artifact mẫu được giữ nguyên tại `fuzzer/output/diagnostics/exactmetrics-targeted-20261026/request.json`:

| Đo | Kết quả |
| --- | ---: |
| File v3 ban đầu | 1.012.448 byte |
| File v4 qua exporter PHP thật, JSON gọn | 357.055 byte |
| Giảm | **64,73%** |
| Callback đăng ký / đã chạy / blindspot khôi phục | 181 / 22 / 159 |

Sau khi thêm lại map blindspot và đổi nhãn schema về v3, đối tượng JSON bằng hoàn toàn bản cũ. Kết quả quan sát của validator cũng bằng nhau; file lịch sử không đổi. Đây là số đo trên một request, không phải cam kết phần trăm cho mọi plugin.

- 11 kiểm tra mới: tương đương v3/v4, metadata child/REST, callback inactive, alias/missing explicit ID, tham chiếu lỗi, PHP exporter thật, giá trị `false`/`0`/`null`/Unicode, ghi JSON gọn, lỗi encoding/write/rename và lỗi JSON có tên file.
- Kiểm tra hiện có: validator 13, bootstrap 7, UOPZ metadata 5 đều qua. Module generated runner có một kiểm tra cũ không khớp chuỗi lệnh cài Contact Form 7.
- Bộ toàn dự án ban đầu: 700 test, 16 failure, 1 error, 8 skipped. Lượt cuối bật các kiểm tra PHP mới qua Docker: **703 test, 16 failure, 1 error, 4 skipped**. Nạp phiên bản HEAD của cả ba module Python bị sửa vào bộ nhớ rồi chạy lại 6 phương thức lỗi tái hiện đúng 16 failure/1 error. Các nhóm là thiếu PHP CLI trên Windows, đường dẫn dài và chuỗi bootstrap plugin; không sửa chúng trong task này. Không coi suite toàn dự án là xanh.
- Smoke HTTP trên web container: HTTP 200, request schema v4 **362.359 byte**, Zend **31.403 byte**, target callback `get_posts` chạy, request/run ID khớp và khôi phục 159 blindspot. Đây là kiểm tra ghi/đọc evidence, không phải fuzzing PASS hay campaign replay/Pass 2 mới.
- Review độc lập đã rà các consumer; phát hiện alias normalization trong bootstrap và đã có regression test trước khi sửa.

Chạy lại kiểm tra PHP bằng runtime hiện có:

```powershell
$env:HOOKPHUZZ_REQUEST_TEST_CONTAINER = 'code-web-1'
python -m unittest discover -s phuzz-main/code/fuzzer/tests -p test_request_artifact_compaction.py -v
```

## Bằng chứng và phiên bản đang chạy

Thư mục `fuzzer/output/diagnostics/request-artifact-compaction-20261026/` chứa:

- `size-and-equivalence.json`, `real-request-v4.json`: số đo và request mẫu mới.
- `live-smoke.json`, `live-request-v4.json`, `live-zend.json`: bằng chứng HTTP thực tế.
- `full-suite.log`, `full-suite-final.log`, `baseline-failures.json`, `baseline-failures.log`: kết quả kiểm tra và đối chiếu HEAD.
- `change-manifest.json`, `compaction-source.patch`: SHA-256 và diff của bốn file production trong task.
- `uopz_hook_wp.before.php`: bản PHP trong web container trước khi áp dụng.

Đã copy PHP mới vào `/var/www/fuzzer/hook_coverage/uopz_hook_wp.php` của `code-web-1`, lint thành công và graceful reload Apache; HTTP xác nhận schema v4. Docker image chưa rebuild trong task này. Wrapper bình thường dùng `up ... --build`, nên lượt chạy qua wrapper sẽ build từ source mới. Nếu tự tạo container từ image cũ mà bỏ build, PHP có thể vẫn là v3; Python mới đọc được cả hai.

## Khôi phục và giới hạn tương thích

Để dừng sinh v4 trên container hiện tại, copy `uopz_hook_wp.before.php` trở lại đường dẫn PHP trên và reload Apache. Muốn khôi phục source, dùng diff trong `compaction-source.patch` để xem đúng bốn file đã đổi; không reset các thay đổi khác trong working tree.

**Giữ Python reader mới khi khôi phục producer:** reader mới đọc cả v3/v4; reader cũ không khôi phục được map blindspot bị lược khỏi v4. Nếu công cụ ngoài repo đọc trực tiếp map đó, cần dùng helper mới hoặc tạo bản mở rộng của artifact để điều tra, không ghi đè bản gốc. Không đổi toàn bộ về reader cũ rồi diễn giải v4 như v3.

Thay đổi không làm `/shared` tự dọn: request vẫn tích lũy, chỉ nhỏ hơn. Dữ liệu không mã hóa được vẫn không thể tạo artifact hợp lệ; hiện có thông báo cụ thể thay vì công bố file JSON rỗng.

Không hoàn thành config plugin mới trong task này, nên không thêm dòng checklist.
