# Một baseline callback trước khi fuzz

Ngày: 2026-11-01. Trạng thái: thiết kế chờ người dùng duyệt.

## Mục tiêu và quyết định

Người dùng chọn hướng 1: param có bằng chứng runtime được đưa vào config;
config mới qua một lần baseline để xác nhận request tới đúng callback rồi
được phép fuzz. Bỏ trial và Pass 2 bắt buộc nhằm xác minh lại toàn bộ param.
Mục tiêu là giảm độ phức tạp và lượt gửi request trước khi fuzz.

Đây là thay đổi tập trung trong workflow online-linked hiện có, không thêm
mode hay cờ CLI. Tài liệu này chưa xác nhận thay đổi đã được triển khai.

## Các hướng đã cân nhắc

1. **Một baseline callback — người dùng đã chọn.** Giữ bằng chứng request
   của config thực tế tới đúng callback, đổi lại còn một lượt gửi kiểm tra.
   Không yêu cầu mọi param đã khám phá phải cùng xuất hiện trong lần chạy đó.
2. **Fuzz ngay từ bằng chứng discovery.** Ít lượt gửi và ít logic hơn, nhưng
   chưa biết config sau khi dựng có tái hiện được request đã quan sát không.

## Hành vi mới

- Admission lúc discovery giữ nguyên: chỉ nhận param có runtime access
  được policy hiện tại chấp nhận, ghép đúng callback, request/run và nguồn
  input. Không biến tên param phỏng đoán thành param đã quan sát.
- Dựng config bằng bằng chứng và giá trị request hiện có. Giữ context
  endpoint, method, auth, transport và selector cố định; không ghép tùy ý
  các context khác nhau. Giá trị dùng để mở nhánh vẫn phải được giữ trong
  baseline và seed theo cơ chế hiện có.
- Bỏ vòng coherent replay-input trials, yêu cầu từng param được đọc lại
  trong trial, và Pass 2 bắt buộc khỏi đường quyết định cho phép fuzz.
  Không dùng việc thiếu một param cũ trong baseline làm lý do chặn config.
- v0 và config con dùng cùng policy baseline. Mỗi lần xét khởi động/handoff
  gửi một baseline, không có trial trước baseline. Việc revalidate khi
  resume/reactivate tiếp tục theo lifecycle hiện có và không tạo vòng trial.
- Baseline chỉ đạt khi request thực tế tới đúng callback, artifact có đủ
  correlation hiện cần thiết, request/config có đúng method và auth context,
  tiến trình gửi thành công và còn trong deadline. Các kiểm tra này không
  đòi hỏi tập param quan sát bằng toàn bộ tập param của config.
- Sau baseline đạt, chỉ handoff khi parent đã dừng thành công và còn budget.
  Baseline lỗi không khởi động child; giữ evidence và xử lý parent/pending
  work theo lifecycle hiện có.

## Các mặc định triển khai do agent đề xuất

- Giữ policy HTTP hiện có: không tự cho mọi HTTP 200 hoặc callback reach
  thành công; còn phải qua các điều kiện baseline nêu trên. Không mở rộng
  việc nhận lỗi HTTP hay redirect thiếu bằng chứng. Không đổi WordPress
  login/quyền/nonce overrides trong thay đổi này.
- Ghi policy mới rõ ràng trong gate/state/summary, dự kiến
  `verification_policy: callback_baseline_v1`. Baseline đạt không được ghi
  thành Pass 2 đạt; không tạo số `accepted/total` giả.
- Export chấp nhận gate baseline mới có policy được nhận diện và `passed`
  hợp lệ, đồng thời giữ kiểm tra hash, config type và loại probe/replay-only.
  Với state cũ không có policy mới, tiếp tục yêu cầu gate Pass 2 cũ đầy đủ;
  không biến `passed: true` trống bằng chứng thành config được phép export.
- Resume không bỏ qua baseline cần revalidate và không diễn giải artifact
  trial cũ thành bằng chứng của policy mới. Bản export lịch sử giữ nguyên.
- Điều chỉnh phần thời gian dự trữ cho baseline và handoff thực tế; bỏ dự
  trữ cho lượt trial đã loại. Giữ campaign/candidate deadline, giới hạn
  versions/candidates và credit từ tiến triển runtime.

## Phạm vi cần sửa

- `phuzz-main/code/fuzzer/online_linked/coordinator.py`: gate v0, tạo child,
  vòng trial, handoff, budget và các nhánh state/resume liên quan.
- `phuzz-main/code/fuzzer/online_linked/export.py`: nhận policy baseline mới,
  summary và phân biệt bằng chứng runtime với baseline/Pass 2/fuzzing.
- Test coordinator, export và những caller/fixture thực sự bị ảnh hưởng;
  cập nhật guide/README mô tả gate. Xóa helper/import chỉ còn dùng cho trial
  khi đã xác nhận không còn caller. Giữ verifier Pass 2 nếu còn caller khác.

Không thay thuật toán mutation, cơ chế thu Zend/UOPZ, chính sách admission
param, login/quyền/nonce, hoặc thêm hệ thống thử giá trị thay thế cho trial.

## Kiểm chứng và tiêu chí đạt

1. Param đã được admission nhưng không được đọc lại trong baseline không
   chặn worker khi mọi điều kiện callback baseline đều đạt.
2. Sai callback/request/run/plugin/method/auth, artifact lỗi, sender lỗi
   hoặc hết deadline vẫn chặn; HTTP/redirect policy hiện có được bảo toàn.
3. Một config con được chấp nhận chỉ có một baseline send trong quyết định
   handoff, không gọi trial hoặc verifier Pass 2 để cho phép fuzz.
4. Export nhận gate mới hợp lệ; từ chối gate thiếu bằng chứng, policy không
   biết hoặc hash đổi. State cũ vẫn qua điều kiện cũ, không được nới ngầm.
5. Parent/pending work, budget và resume còn hoạt động; summary không gọi
   baseline đạt là Pass 2 hoặc fuzzing PASS.
6. Sau unit/regression, chạy một campaign Docker có phạm vi hẹp với fixture
   hiện có để đối chiếu số lượt gửi và worker thực sự khởi động. Không suy
   ra tốc độ hay độ phủ cải thiện khi chưa có phép đo mới.

## Giới hạn và checklist

Baseline chứng minh request đã tới callback trong môi trường instrumented;
không chứng minh callback chạy hết, tất cả param được dùng cùng lúc, đã tìm
đủ param hay đã phát hiện lỗ hổng. Bỏ trial cũng bỏ các lần tự điều chỉnh
giá trị từ comparison hint ở bước chuẩn bị; một số seed có thể vào nhánh
nông hơn. Mutation/CMPLOG của fuzzer không nằm trong phạm vi loại bỏ.

Tác vụ hiện tại mới viết thiết kế, chưa hoàn tất plugin config nên không
thêm dòng hoàn thành vào `plugin-test-checklist.md`. Khi triển khai và thực
sự hoàn tất một config cụ thể, cập nhật đúng dòng theo AGENTS.md, tách rõ
generation, runtime evidence, baseline, Pass 2 không chạy, và fuzzing result.

Các lựa chọn nội bộ như tên helper hoặc cách sắp lại test thuộc người triển
khai; không thêm abstraction hay compatibility layer ngoài nhu cầu trên.
