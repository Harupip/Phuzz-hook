# Đề xuất: tiếp tục khi có tiến triển, dừng khi chỉ lặp việc cũ

Ngày: 2026-10-20. Trạng thái: đề xuất để xem xét; chưa triển khai.

## 1. Mục tiêu

Một candidate được chạy quá mốc 120 giây nếu vẫn xác nhận được thông tin mới.
Candidate không có tiến triển phải dừng, giữ lại final đã xác minh và config
`.partial.json` cho phần chưa hoàn tất.

Không thay tiêu chuẩn runtime, replay hoặc Pass 2 để có thêm file final.
Không mặc định coi mọi tên param quan sát được là param đã xác minh.

## 2. Vấn đề hiện tại đã kiểm tra

`online_linked/coordinator.py` hiện có hai deadline cho từng candidate:

- Ban đầu: `max_seconds`, hiện cấu hình 30 giây.
- Tuyệt đối: `hard_seconds`, mặc định được tính từ ngân sách ban đầu, hiện 120 giây.

`_extend_progress_budget()` chỉ gia hạn đến deadline tuyệt đối. Có thông tin
mới sau khi đã dùng hết trần này cũng không giúp candidate tiếp tục.

Ngoài ra, code hiện cấp credit cho `pending_verification`: param mới có bằng
chứng đề xuất nhưng vẫn đang chờ probe. Vì vậy, có nhiều tên mới không đồng
nghĩa chương trình đã kiểm chứng được nhiều input có ích.

Run `ad-inserter-20261019T153555Z`, candidate backend:

- 23 credit thuộc loại `pending_verification`.
- Ba probe được chấp nhận: `ads-txt`, `adsense-authorization-code`,
  `adsense-client-id`.
- Chưa có vòng `replay_input_trials`, chưa tạo được version con.
- Dừng `HARD_CANDIDATE_TIME_CAP`; chỉ có v0 và một draft partial giữ 26
  danh tính param đã quan sát. Số 26 không phải 26 param đã qua Pass 2.

Vấn đề cần giải quyết gồm cả cách gia hạn và thời điểm chuyển sang xác minh;
chỉ tăng số 120 hoặc bỏ một lệnh `min()` chưa giải quyết đầy đủ.

## 3. Phương án đề xuất

### 3.1. Deadline mặc định phụ thuộc tiến triển cuối cùng

Giữ `max_seconds` làm cửa sổ chạy ban đầu và khoảng thời gian được cấp sau
mỗi tiến triển thật. Với cấu hình hiện tại, khoảng này là 30 giây.

Khi xác nhận thông tin mới, bảo đảm còn ít nhất một cửa sổ để làm tiếp:

```text
deadline_mới = max(deadline_hiện_tại, thời_điểm_hiện_tại + cửa_sổ_tiến_triển)
```

Không cộng dồn 30 giây cho từng tên trong một danh sách vừa thu được.
Một loạt phát hiện cùng thời điểm không mua trước hàng chục phút chạy lại.

Nếu đã có param mới được probe xác nhận, còn phải chừa đủ ngân sách cho một
vòng trial, replay và xác minh/handoff. Tái sử dụng cách ước tính đang có
`3 * _sender_seconds`, không thêm bộ ước lượng mới:

```text
deadline_mới = max(deadline_mới, hiện_tại + dự_trữ_xác_minh)
```

Đây là dự trữ cho công việc xác minh cụ thể, không phải credit cho retry.
Chỉ cấp khi có bằng chứng mới hợp lệ, không tự cấp lại mỗi vòng poll.

Mọi deadline vẫn bị chặn bởi ngân sách campaign thực tế còn lại.
Nếu người chạy chủ động đặt trần tuyệt đối cho candidate, cũng phải tôn trọng.

### 3.2. Bỏ trần 120 giây tự sinh; giữ ý nghĩa của trần được đặt rõ ràng

Không âm thầm biến một tùy chọn tên `hard` thành giới hạn có thể vượt.

Đề xuất thay đổi chính xác:

- Khi không truyền `--hard-candidate-seconds`: không tự tạo trần tuyệt đối
  bằng bốn lần ngân sách ban đầu nữa; candidate dừng theo deadline tiến triển
  và ngân sách campaign.
- Khi có truyền `--hard-candidate-seconds`: đó vẫn là trần tuyệt đối do người
  chạy yêu cầu, không được vượt.
- Log và state phải phân biệt rõ trần không được đặt với trần đã cạn.
  `None` không được ghi thành `0` vì hai ý nghĩa khác nhau.

Như vậy, workflow mặc định được phép qua mốc 120 giây khi đang tiến triển,
nhưng tùy chọn giới hạn tài nguyên rõ ràng vẫn có ý nghĩa.

### 3.3. Chỉ gia hạn cho tiến triển thật

| Sự kiện | Xử lý đề xuất |
| --- | --- |
| Tên param mới qua `isset`, chưa được probe | Giữ vào hàng chờ; probe trong ngân sách còn lại, không gia hạn dài chỉ vì có thêm tên |
| Probe xác nhận param mới, correlation hợp lệ | Gia hạn một lần cho danh tính param đó, chuyển ưu tiên sang xác minh config |
| Callback mới có bằng chứng runtime hợp lệ | Ghi vào hàng chờ và xử lý theo cơ chế campaign hiện có; callback con không kéo dài parent vô hạn |
| Cùng param được kiểm tra lại với bằng chứng không tiến thêm | Không gia hạn |
| Chỉ đổi request ID, run ID, version hoặc giá trị fuzz | Không gia hạn |
| Retry lỗi, poll artifact cũ, callback đã biết | Không gia hạn |
| HTTP 200 hoặc worker vừa khởi động | Không đủ điều kiện gia hạn |

Tái sử dụng khóa chống trùng hiện có. Với param, danh tính phải gồm callback
và `(name, source, location)`, không chỉ tên. `GET[id]` khác `POST[id]`.
Version hoặc request mới không làm một param cũ thành param mới.

Không thêm suy đoán “nhánh mới” từ tên file config hay giá trị fuzz. Chỉ bổ sung
loại credit nhánh/coverage nếu có yêu cầu và bằng chứng riêng trong task sau.

### 3.4. Ưu tiên hoàn thành một config trước khi vét hết hàng probe

Sau khi có probe xác nhận được param mới:

1. Tạo đề xuất từ nhóm bằng chứng đã có.
2. Chạy trial để kiểm tra request thực tế.
3. Nếu trial và Pass 2 đạt, tạo version/config mới và replay theo gate hiện có.
4. Lưu kết quả rồi tiếp tục probe các param còn lại trong ngân sách còn hiệu lực.

Không bắt buộc xử lý hết danh sách pending mới được chuyển sang bước 2.
Các proposal không phù hợp cùng request vẫn phải tách nhóm theo cơ chế hiện có.
Không gộp tất cả quan sát vào một config final chưa được kiểm chứng.

Với backend Ad Inserter, đây là điểm cần thử: sau probe đầu tiên có ích,
chuyển sang trial thay vì tiếp tục tiêu ngân sách gom nhiều tên.
Trial có thể thất bại; lúc đó giữ lý do thất bại và draft, không nâng thành final.

### 3.5. Điều kiện dừng

Candidate dừng khi gặp một trong các điều kiện:

- Hết cửa sổ tiến triển và không còn lượt xác minh đã được cấp ngân sách hợp lệ.
- Hết ngân sách campaign.
- Chạm trần candidate được người chạy đặt rõ ràng.
- Chạm giới hạn version/candidate khác đang tồn tại, hoặc có lỗi thực thi cần dừng.

Task này chỉ đổi chính sách thời gian. Giới hạn version/candidate không tự bị bỏ.
Nếu chúng cản khám phá, state phải ghi đúng giới hạn đã chạm để xem xét riêng.

Giữ timeout hữu hạn cho từng HTTP request, Docker command và bước xác minh.
Gia hạn do tiến triển không cho phép một lệnh con treo vô hạn.

## 4. Ví dụ dễ kiểm tra

Ví dụ cửa sổ 30 giây, bỏ qua phần dự trữ xác minh để dễ đọc:

| Thời điểm | Việc xảy ra | Deadline |
| --- | --- | --- |
| 0 giây | Bắt đầu | 30 giây |
| 20 giây | Probe xác nhận param A mới | 50 giây |
| 40 giây | Chỉ chạy lại A | Vẫn 50 giây |
| 45 giây | Probe xác nhận param B mới | 75 giây |
| 70, 95, 120 giây | Mỗi lần đều xác nhận param mới | 100, 125, 150 giây |
| 120–150 giây | Không có tiến triển mới | Dừng ở deadline hiệu lực |

Candidate được qua 120 giây vì có tiến triển. Nếu chỉ chạy lại A, nó đã dừng
ở 50 giây. Thời gian thực tế có thể gồm dự trữ xác minh, nhưng phải được log rõ.

## 5. Dừng rồi lưu gì

Giữ cơ chế export vừa bổ sung:

- `final-configs/`: chỉ config đạt gate hiện có; không hạ chuẩn để tăng số file.
- `partial-configs/*.partial.json`: phần khám phá chưa xong, ghi rõ lý do dừng,
  param đã xác minh/chờ xác minh và `fuzzing_ready=false`.
- `final-config-summary.json`: hai danh sách `exported_configs` và
  `partial_configs` riêng; không tính partial vào số final.

Ví dụ kết luận đúng: “có final cho nhóm A; còn nhóm B chưa xác minh; dừng vì
không có tiến triển mới”. Không ghi “đã tìm hết param”.

Nếu thêm lý do dừng mới như `NO_NEW_PROGRESS`, exporter phải nhận diện được
để vẫn tạo draft; hiện điều kiện partial còn dựa vào các chuỗi budget/time/limit.
Không được đổi reason trong coordinator rồi vô tình làm mất file partial.

## 6. State, log và resume

State cần thể hiện đủ:

- Chính sách budget đang dùng: tiến triển hay trần tuyệt đối.
- Thời gian đã chạy; deadline còn lại; campaign còn bao nhiêu.
- Trần candidate nếu được đặt rõ ràng.
- Tiến triển được công nhận gần nhất và khóa chống cấp credit trùng.
- Dự trữ đang cấp cho lần xác minh nào.
- Pending work và lý do dừng.

Tái sử dụng state/checkpoint hiện có, chỉ thêm trường khi thiếu bằng chứng cần đọc.
Log mỗi lần gia hạn phải cho thấy sự kiện, deadline trước/sau và giới hạn chi phối.

Resume không được làm mới toàn bộ thời gian hoặc xóa danh sách credit đã dùng.
Phải giữ phần thời gian còn lại bằng clock epoch mới, kiểm tra context/hash và
chạy lại gate theo quy trình hiện có. Không lấy thời điểm monotonic của process
cũ đem so trực tiếp với process mới.

Checkpoint cũ dùng trần tự sinh không được âm thầm chuyển chính sách khi resume.
Giai đoạn đầu nên báo lỗi không tương thích có hướng dẫn tạo run mới; không cần
viết migration tự động trong thay đổi này.

## 7. Những phần code cần xem/sửa khi được triển khai

| Phần | Phạm vi |
| --- | --- |
| `online_linked/coordinator.py` | Tạo/gia hạn deadline, credit pending/verified, ưu tiên handoff, kiểm tra hết giờ, checkpoint/resume và parser của trần candidate |
| `online_linked/export.py` | Nhận diện lý do dừng mới; giữ hai loại output riêng |
| `tests/test_online_linked_coordinator.py` | Fake clock, progress dedupe, handoff và resume |
| `tests/test_online_linked_export.py` | Dừng do không tiến triển vẫn xuất partial, không đổi gate final |
| `online_linked/README.md` và guide budget | Mô tả đúng chính sách mới, trần đặt rõ ràng và ranh giới bằng chứng |
| Wrapper/env tests nếu cần | Kiểm tra default/CLI tương thích với chính sách mới; không tự thêm menu/flag không cần thiết |

Không sửa logic plugin, thuật toán mutation, checker lỗ hổng hay xử lý lỗi worker
DST trong cùng thay đổi này. Không commit/push nếu chưa được yêu cầu.

## 8. Test bắt buộc

1. Có param mới hợp lệ sát mốc 120 giây: candidate được tiếp tục qua mốc đó
   khi không có trần tuyệt đối đặt rõ ràng.
2. Chỉ lặp param cũ dù request/version đổi: deadline không tăng.
3. Một loạt guard-only xuất hiện cùng lúc: không cộng thành hàng chục cửa sổ chạy.
4. Một param probe được xác nhận: chuyển sang trial trước khi vét hết hàng pending.
5. Xác minh thất bại không được biến thành credit mới bằng retry vô hạn.
6. Đủ dự trữ cho một lượt xác minh; lượt đó vẫn chịu campaign/request timeout.
7. Campaign hết giờ hoặc trần candidate đặt rõ ràng hết giờ: dừng dù có progress.
8. Evidence đến muộn sau deadline không tự hồi sinh candidate đã hết hạn.
9. Resume giữ credit và ngân sách còn lại; checkpoint chính sách cũ bị từ chối rõ.
10. Lý do dừng mới vẫn xuất partial nếu có quan sát, giữ nguyên final đã xác minh.

Chạy test với timeout và temp directory trong workspace trên Windows.
Chỉ báo số test đã đạt và số skip/lỗi thực tế; không gọi cả suite là xanh nếu có skip.

## 9. Kiểm chứng bằng Ad Inserter sau khi sửa

Chạy một run mới, giữ các giá trị initial hiện tại để so sánh có ý nghĩa.
So với run `ad-inserter-20261019T153555Z`:

- Backend có được tiếp tục khi có tiến triển thật và có bắt đầu trial không?
- Có trường hợp vượt 120 giây nhờ param mới, thay vì chỉ do lệnh bị chậm không?
- Đoạn chỉ lặp input cũ có thực sự ngừng gia hạn không?
- Bao nhiêu final, bao nhiêu partial; param nào mới được xác minh?
- Mỗi final có đúng callback/request correlation, replay và Pass 2 không?
- Worker có được dừng sau khi run kết thúc không?

Đạt yêu cầu về chính sách thời gian không bắt buộc backend phải có final:
plugin hoặc request có thể còn điều kiện chưa thỏa. Khi đó cần nêu lỗi thực tế,
không tăng giờ để che lỗi và không dùng partial làm bằng chứng fuzzing PASS.

Cập nhật hai checklist theo artifact mới sau khi có run kiểm chứng.
Tài liệu đề xuất này chưa tạo/sửa config, nên không thêm dòng hoàn thành config.

## 10. Giới hạn và quyết định đề nghị

Chọn: deadline theo tiến triển thật, ưu tiên hoàn thành vòng xác minh, mặc định
không tự áp trần candidate 120 giây; vẫn giữ trần campaign và trần candidate
nếu người chạy đặt rõ ràng.

Candidate liên tục có tiến triển có thể giữ lượt chạy lâu hơn và làm các candidate
sau phải chờ. Đây là đánh đổi chấp nhận được cho thay đổi nhỏ hiện tại; điều phối
luân phiên là phạm vi riêng, chưa đề xuất triển khai cùng lúc.

Trần campaign vẫn là giới hạn tài nguyên thật: code hiện mặc định initial 3.600
giây và hard campaign mặc định ít nhất 86.400 giây. Không được mô tả 3.600 giây
là giới hạn tuyệt đối khi cơ chế progress vẫn cho tăng tới hard campaign.

Chưa triển khai, chưa chạy test hay Docker cho phương án mới.
