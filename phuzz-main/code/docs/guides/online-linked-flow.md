# Luồng online của HookPhuzz

Cập nhật: 2026-09-13. Tài liệu mô tả `-Mode online-linked` theo mã hiện tại, bao gồm batching probe, provenance/evidence, COOKIE runtime opt-in, direct-argument Zend instrumentation, trạng thái lỗi và kiểm tra ngân sách. Đã có fresh fixture/Docker gates cho các thay đổi này; chưa có lần chạy Docker toàn tuyến với real plugin xác minh tất cả 10 bước.

Kế hoạch bổ sung: [Online-linked completion](../../../../../docs/superpowers/plans/2026-09-06-online-linked-completion.md). Những phần ghi “còn thiếu” bên dưới là công việc tương lai, không phải tính năng đã hoạt động.

## 1. Phân biệt các mode

| Mode | Cách chạy hiện tại |
| --- | --- |
| `generated` | Xuất config theo pipeline generated; có thể bật `-UseZendDiscovery`. Không bị thay đổi bởi bản sửa vòng đời online-linked. |
| `online` | Coordinator cũ chọn một target, tạo các phiên bản bất biến; replay gate kiểm tra callback nhưng chưa gọi `verify_pass2_contract()` như online-linked. Không coi hai mode là tương đương. |
| `online-linked` | Đọc snapshot `suggested_seeds.json`, xử lý từng candidate tuần tự; mỗi candidate có `v0` và các worker con được kiểm tra replay/Pass 2. |

Các đường dẫn source bên dưới tính từ `phuzz-main/code`.

## 2. Luồng đang được nối trong code

```mermaid
flowchart TD
    A[Docker, plugin, instrumentation, run ID] --> B[Bootstrap WordPress và REST]
    B --> C[Snapshot seed và callback registry]
    C --> D[Chọn candidate tiếp theo]
    D --> E[Tạo v0 và kiểm tra cấu trúc]
    E --> F{Có tham số fuzz?}
    F -->|Có| G[Chạy PHUZZ v0]
    F -->|Chưa có| H[Chạy v0 replay-only]
    G --> I[Ghép request và Zend evidence]
    H --> I
    I --> J{Tham số Zend mới hợp lệ?}
    J -->|Có| K[Tạo config con bất biến]
    K --> L[Dừng parent thành công]
    L --> M[Replay con và Pass 2]
    M -->|Đạt và còn ngân sách| G2[Chạy worker con]
    G2 --> I
    M -->|Lỗi, còn ngân sách| R[Thử khởi động lại parent]
    R --> I
    J -->|Không| N[Tiếp tục quan sát trong ngân sách]
    N --> I
    I -->|Runtime registration A→B| X[Classify B + identity dedupe]
    X -->|HTTP metadata + replayable method| Y[Queue B with lineage]
    X -->|Internal, ambiguous, setup missing| Z[Blocked with evidence]
    Y --> D
```

Sơ đồ biểu diễn đường đi thành công và nhánh phục hồi chính. Hết thời gian, hết số phiên bản, worker lỗi hoặc tìm thấy vulnerability có xử lý kết thúc riêng. Các worker đã chạy không được sửa config tại chỗ.

## 3. Đối chiếu mục tiêu 10 bước

| Bước | Mục tiêu | Hiện trạng code và giới hạn |
| --- | --- | --- |
| 1 | Khởi tạo Docker, plugin, instrumentation và run ID | Có trong wrapper. HTTP 200 và bật biến môi trường chưa chứng minh Zend/UOPZ đã tạo evidence hợp lệ. |
| 2 | Truy cập entrypoint, thu hook/route đăng ký trong runtime | Có bootstrap và hook đăng ký runtime; online-linked đọc registration trong request artifact, xác minh parent/request ID, cập nhật registry và queue HTTP child. Internal/ambiguous registrations vẫn blocked. |
| 3 | Request khởi đầu đúng endpoint, method, auth | Có chuyển seed thành request/config và các gate. Chưa tự chuẩn bị đầy đủ auth, nonce, dữ liệu ứng dụng cho mọi plugin; replay probe không đồng nghĩa đã xác minh method/ngữ cảnh. |
| 4 | Replay tìm tham số đúng callback, nguồn input | Có ghép exact request ID/run ID/plugin và convergence kiểm tra provenance. Raw direct-argument read giữ provenance từ root `FETCH_FUNC_ARG`; direct `read` hoặc guard `isset`/`empty` có key trong request bucket đều có thể được nhận. |
| 5 | Tạo, kiểm chứng config đầu; xử lý chưa có tham số | Có `replay_only` và `fuzzing_ready`; v0 phải qua replay callback/provenance và Pass 2 trước khi fuzz. Seed không có tham số chỉ chạy probe/replay bounded hoặc ghi blocked. |
| 6 | Chạy PHUZZ khi config đủ điều kiện | Có cho candidate đang được xử lý. Worker con phải qua replay/Pass 2 và còn ngân sách. |
| 7 | Thu coverage, lỗi, tham số mới, so sánh khi fuzz | Có trong fuzzer và instrumentation; coordinator đọc cặp request/Zend. |
| 8 | CmpLog mutation đúng tham số rồi gửi lại | Có `_ingest_cmplog_hints()` → `ff_mutate()` → `ff_send_request()` → coverage/lỗi. Có test đơn vị; không mặc định mọi phép so sánh đều được hỗ trợ hoặc mọi nhánh đều tới được. |
| 9 | Tạo config khi nhánh/tham số mới, giữ giá trị mở nhánh | Tạo config theo tham số Zend mới, giữ evidence/value riêng cho từng parameter và map COOKIE vào bucket `cookies`. Không tạo config chỉ vì coverage mới. |
| 10 | Chạy config mới; action mới quay về bước 2, tham số mới về bước 3 | Child parameter config giữ request values rồi replay/Pass 2. Runtime HTTP registration và pending probe được queue với lineage/evidence riêng, dedupe theo context/input, candidate cap và campaign budget; internal/ambiguous child có evidence blocked. |

### Giới hạn giữ giá trị mở nhánh

`advance_online_version()` gọi `materialize_convergence_seeds(..., for_replay=False)`, xuất config rồi sao chép config đó sang replay-only. Materializer thay tham số đã chứng minh bằng `FUZZ`; exporter khởi tạo giá trị fuzz bằng `fuzz`. `_force_replay_only()` chỉ cố định config vừa xuất, không phục hồi giá trị request gốc.

Ví dụ kiểm tra bằng helper hiện tại:

```text
request mở nhánh: mode=deep
Zend quan sát: mode, detail
replay con: mode=fuzz, detail=fuzz
```

Nếu `detail` chỉ được đọc khi `mode == "deep"`, replay có thể mất nhánh. Cần giữ request chứng cứ và chứng minh replay vẫn tới nhánh trước khi khởi động worker con. Không hard-code `deep` hoặc giá trị của plugin vào thuật toán.

### Giới hạn auth và đăng ký hook

Exporter mang theo dữ liệu cookie có trong seed; nó không tự chạy toàn bộ login automation. Môi trường UOPZ có các override liên quan login/capability/nonce, nên callback reachability trong môi trường này không tự chứng minh hành vi auth nguyên bản của plugin.

Một `add_action()` mới có thể chỉ là hook nội bộ, không có URL gọi trực tiếp. Muốn quay về bước 2 phải xác định hook loại nào, parent request nào làm nó xuất hiện và điều kiện để tái lập đăng ký. Không tự suy ra HTTP endpoint từ tên hook bất kỳ.

### Runtime COOKIE opt-in

Online-linked có thể bật khám phá COOKIE bằng `--runtime-cookie-probes`. Mặc định tùy chọn này tắt, nên generated/static discovery và các lệnh online-linked không truyền cờ vẫn giữ policy cũ; `parameter_seeds.py` vẫn block COOKIE tĩnh trên diện rộng.

Khi bật, chỉ COOKIE có runtime access được gán đúng callback và request artifact cùng `run_id`/`request_id` mới được nhận. Artifact chỉ lưu danh sách tên cookie, không lưu giá trị. `isset`/`empty` không có key tương ứng vẫn là candidate pending; khi probe đã materialize đúng key và giữ exact correlation, guard có thể được admission. Guard không bị đổi tên thành `read`; probe marker synthetic vẫn không phải observed value. COOKIE được giữ ở mapping `COOKIE` → `cookie` → seed/config `cookies`, nên không nhập với POST trùng tên.

Giá trị cookie do setup quản lý, nhất là login cookie, không được lấy từ artifact để fuzz hoặc ghi đè. Exporter/request preparation vẫn gửi cookie qua bucket riêng; verifier kiểm tra membership tên cookie cùng callback, raw read và exact artifact IDs. Wrapper PowerShell chưa đổi; cờ được truyền ở coordinator online-linked.

### Queue probe và provenance của evidence

Khi một probe chưa đủ điều kiện admission nhưng đã có artifact correlate được, coordinator giữ outcome `pending` gồm `candidate`, convergence report và evidence nguồn. Mỗi queue item có bản sao riêng; không dùng report hoặc request/Zend evidence của probe cuối cho các candidate trước đó.

Ví dụ: probe `a` có thể phát hiện candidate `c`; `c` được chạy với merged seed report và evidence của `a`, trong khi candidate `b` đã có trong queue vẫn giữ report/evidence ban đầu. Candidate mới chỉ được giữ pending cho tới khi có correlated runtime `read` hoặc guard access đúng callback/request/run và bucket; không tự admit `unexpected_parameters`.

Dedupe dùng parent/callback/context, source/location và toàn bộ input request (`query_params`, `body_params`, `json_params`, `cookies`), bỏ qua request ID và metadata. Vì vậy cùng candidate với input mới có thể retry trong `MAX_PROBE_ATTEMPTS`; cycle hoặc cùng input không lặp vô hạn. Deadline probe là phần ngân sách riêng, phần còn lại dành cho export/replay/handoff child; accepted evidence vẫn được giữ nếu probe sau timeout hoặc thất bại.

### Batch artifact reader và evidence gate

`online_linked_evidence.read_runtime_batch()` đọc request/Zend theo một lần `docker compose exec -T web php -r`; PHP trả đúng một envelope `pairs` + `stats`. Reader chỉ nhận JSON object hợp lệ, giữ nguyên kiểu scalar/object/list, kiểm tra `request_id`, tên file, `run_id`/`legacy_run_id` và `target_plugin`; lỗi transport, timeout hoặc payload hỏng đều fail closed. File `.json.tmp.*` không được coi là artifact cuối. Payload được chuyển dưới dạng JSON gốc trong envelope rồi decode bằng Python, tránh mất độ chính xác số nguyên lớn khi PHP encode lại.

Coordinator dùng reader này cho polling worker; production path không còn list/load từng file. `state.json` ghi `evidence_scan` gồm số file, số cặp, missing Zend, invalid payload, thời gian transport và ngân sách còn lại. Cặp chưa có Zend chỉ là `RETRY`; chỉ cặp correlate đầy đủ mới được đánh dấu seen và chuyển vào admission.

Sau khi v0 replay và callback/provenance đã đạt (thêm Pass 2 nếu v0 là `fuzzing_ready`; v0 `replay_only` chỉ được phép probe), cặp request/Zend exact của v0 được giữ với `evidence_origin: v0_gate`. Coordinator khởi động worker trước, kiểm tra parent container, rồi đưa chính cặp gate đó qua `_handle_convergence_result()` trước polling batch đầu tiên. Probe lần đầu ghi `evidence_origin`, `request_id`, `remaining_budget_seconds` và `first_probe_delay_seconds`; origin `worker_poll` chỉ xuất hiện với evidence đọc từ batch sau đó. Parent checks, auth/provenance, deadline, replay và Pass 2 vẫn là điều kiện admission; gate không thay thế chúng.

### Review và sửa bổ sung ngày 2026-09-14

Bản tối ưu thay việc gọi Docker đọc từng artifact bằng batch reader và tái dùng evidence gate sau worker startup. Review bổ sung đã sửa:

- **Giới hạn version:** gate kiểm tra `max_versions` trước khi xử lý convergence, tránh tạo thêm probe/child qua nhánh bỏ qua giới hạn của polling.
- **Dọn worker khi gate dừng:** nhánh terminal ngay sau gate gọi `_stop_active_worker()`, tránh để container tiếp tục chạy khi coordinator đã trả về.
- **Callback phụ:** evidence gate đi qua `_discover_runtime_candidates()` trước khi đánh dấu đã xử lý, giữ khả năng mở rộng callback từ runtime registry.
- **Độ chính xác payload:** PHP chuyển chuỗi JSON gốc qua `request_json`/`zend_json`; Python decode thành payload. Không encode lại giá trị request bằng kiểu số PHP, tránh làm tròn số nguyên lớn.
- **Kiểm tra parent:** khi caller truyền timeout, `docker inspect` trả nonzero hoặc output không hợp lệ phải báo `ParentInspectionError/PARENT_INSPECT_FAILED`; không coi trạng thái không xác định là parent còn chạy. Giữ hành vi legacy cho caller không truyền timeout.
- **Tên artifact:** host bắt buộc request và Zend có đuôi `.json`, bên cạnh kiểm tra basename, ID và loại file tạm.

Regression mới đã chạy đỏ trước sửa cho worker cleanup, giới hạn version/gate discovery, raw payload transport và parent inspection. Fixture parent đang chạy được sửa để trả `running` thay vì chuỗi rỗng.

Kết quả kiểm chứng tại lần review này:

| Suite | Pass | Fail | Skip |
|---|---:|---:|---:|
| `test_online_linked_coordinator.py` (lần cuối) | 89 | 0 | 0 |
| `test_online_linked_evidence.py` | 3 | 0 | 0 |
| `test_online_linked_export.py` | 6 | 0 | 0 |
| `test_generated_config_runner.py` | 39 | 0 | 0 |
| `test_probe_sender.py` | 15 | 0 | 0 |
| **Tổng test riêng biệt** | **152** | **0** | **0** |

Các suite chạy qua `python -m unittest discover -s tests -p <pattern>` tại `phuzz-main/code/fuzzer`, với outer subprocess timeout 180 giây. Coordinator được chạy lại sau sửa parent inspection: 89 test, 85.258 giây; tổng trên không cộng trùng các lần rerun. Kiểm tra PHP thật trong container với fixture tạm giữ nguyên số `18446744073709551617`, object rỗng và array rỗng. `git diff --check` đạt.

**Giới hạn bằng chứng:** chưa chạy lại campaign guest/auth sau các sửa bổ sung này. Artifact Luna trước review cho guest `cd9e607f2df97986` và auth `af97f05239823e82` có v1 replay Pass 2 `accepted=1,total=1`, nhưng kết thúc lần lượt `BUDGET_EXPIRED` và `RUNTIME_BATCH_READ_FAILED`. Những artifact đó không chứng minh runtime của bản sửa cuối. Verdict runtime vẫn **PARTIAL**, chưa chứng minh fuzz/coverage/CmpLog hoặc vulnerability discovery toàn tuyến.

### Hết budget khi đang đọc evidence (sửa bổ sung 2026-09-14)

Lượt `20260914T163603Z` có guest kết thúc `RUNTIME_BATCH_READ_FAILED` với detail `RUNTIME_BATCH_TIMEOUT`, dù đã tạo v1 và đạt replay Pass 2. Auth kết thúc ngoài bước đọc nên nhận `BOUNDED_ONLINE_COMPLETE`. Số đếm terminal vì vậy phụ thuộc thời điểm hết budget.

Đã tách `RuntimeBatchTimeout` khỏi lỗi transport khác. Chỉ timeout transport khi đồng hồ đã chạm deadline candidate mới được phân loại `BOUNDED_ONLINE_COMPLETE/BUDGET_EXPIRED`. Hết budget trước polling hoặc output đến sau deadline cũng kết thúc bounded; output muộn không được admit. Timeout khi còn budget, lỗi Docker và output hỏng vẫn là `NOT_VERIFIED`. Không đổi một lỗi terminal đã ghi trước đó thành thành công bounded.

Khi dừng do budget, giữ status và bằng chứng của version đã xác minh; worker vẫn được dừng theo lifecycle hiện có. `evidence_scan.last_attempt_complete=false` và `last_reason` ghi lượt đọc chưa hoàn tất; số đếm/thời gian scan trước đó, nếu có, thuộc lượt thành công trước. Bounded chỉ là hết thời gian chạy, không phải bằng chứng fuzz PASS. Không sửa ngược artifact cũ.

Regression bao phủ timeout tại deadline, output muộn, hết giờ trước polling, timeout sớm và lỗi Docker; kiểm tra không admit/mark-seen output muộn và không mất known_parameters. Suite `test_online_linked*.py`: 99 pass / 0 fail / 0 skip, 36.005 giây, outer timeout 180 giây. Regression output muộn và exception timeout cụ thể được kiểm tra lại sau khi siết assertion; `git diff --check` đạt. Chưa chạy lại campaign guest/auth sau thay đổi phân loại này.

### Direct argument và Zend raw-read evidence

Fixture direct-argument dùng lời gọi thật `hookphuzz_runtime_sink($_POST['data'])`, một helper depth riêng, direct/local reads và các control `isset`/`empty`. Với PHP compile thành root `FETCH_FUNC_ARG` rồi `FETCH_DIM_FUNC_ARG`, extension phải giữ provenance từ root fetch tới dimension read; `isset` hoặc `empty` không được đổi thành `read`, nhưng correlated guard có thể được dùng như presence input.

Fresh Docker gate sau rebuild extension ghi đủ `data`, `helper`, `direct`, `nested` và `local` raw `read`, đồng thời giữ `guard` là `isset` và `empty_guard` là `empty`, với `dropped_event_count=0`. Chi tiết version, image/source parity, opcode dump và raw event summary nằm trong [results report](../../../../docs/superpowers/plans/2026-09-13-online-linked-luna-results.md).

## 4. Cách chạy và ngân sách

Từ `phuzz-main/code`, cần có Docker, `wp-cli.phar`, ZIP plugin và bootstrap config tương ứng. Ví dụ cho plugin đã có sẵn cục bộ:

```powershell
rtk proxy powershell -NoProfile -File .\phuzz.ps1 -Mode online-linked -PluginSlug nmedia-user-file-uploader -UseZendDiscovery -OnlineTimeoutSeconds 60 -OnlineMaxVersions 3 -NoFollowLogs
```

Đây là lệnh chạy, không phải tuyên bố plugin đã PASS trên checkout hiện tại. Nếu tên plugin/config khác, thay bằng slug đã kiểm tra trên máy.

- `OnlineTimeoutSeconds`: 1–120 giây, mặc định 60, **cho từng candidate**; không phải timeout toàn batch hay Docker build/bootstrap.
- `OnlineMaxVersions`: 1–20, mặc định 2, tính cả `v0` và phiên bản đã tạo nhưng replay thất bại.
- `OnlineMaxCandidates`: 1–128, mặc định 32, giới hạn candidate cả initial và runtime expansion.
- `OnlineCampaignTimeoutSeconds`: 1–86400, mặc định 600, wall-clock budget toàn batch; khác timeout từng candidate.
- Không bắt đầu xử lý evidence để mở rộng khi deadline đã hết. Sau khi dừng parent, nếu còn dưới 1 giây thì không bắt đầu replay mới.
- Sau replay, hết ngân sách thì không khởi động worker con hoặc khởi động lại parent.
- Các lệnh Docker đang thực thi và cleanup vẫn có timeout riêng; thời gian thực tổng cộng có thể vượt ngân sách fuzz. Không coi `60` là giới hạn wall-clock cứng cho toàn lệnh.
- Coordinator dừng candidate khi nhận exit code `1337 % 256 = 57`. Batch hiện tiếp tục candidate khác; cần kiểm chứng marker vulnerability giữa các candidate trước khi coi từng kết quả là phát hiện độc lập.
- Runtime child cập nhật registry theo batch; wrapper dùng `--sync-registry` để nạp lại file vào web container trước replay candidate kế tiếp. Refresh lỗi chặn child.

## 5. Artifact và cách đọc kết quả

```text
fuzzer/output/online-seed-generation/<run-id>/suggested_seeds.json
fuzzer/output/online-linked/<run-id>/batch-state.json
fuzzer/output/online-linked/<storage-id>/state.json
fuzzer/output/online-linked/<storage-id>/events.jsonl
fuzzer/output/online-linked/<storage-id>/versions/vN/
fuzzer/configs/online-linked/<plugin-slug>/<storage-id>/versions/vN/vN-config.json
fuzzer/configs/online-linked/<plugin-slug>/<storage-id>/versions/vN/replay/vN-replay.json
fuzzer/output/online-linked/<batch-run-id>/callback-registry.json
```

`storage-id` của candidate là 16 ký tự đầu SHA-256 của candidate run ID để giảm độ dài đường dẫn Windows. Run ID đầy đủ vẫn nằm trong state/evidence. Lấy `state_path` từ từng dòng `batch-state.json`, không tự ghép tên thư mục từ plugin/hook. Batch state ghi `max_candidates`, `campaign_seconds`, `campaign_status`, expansion events và lineage của candidate runtime. Wrapper in batch state và `state_path` thực tế.

| Trạng thái/lý do | Cách hiểu |
| --- | --- |
| `complete_with_skips` | Batch đã xử lý hết hàng đợi nhưng có candidate lỗi/chưa xác minh hoặc child bị chặn. CLI trả 0 để wrapper hoàn tất; xem trạng thái và mã lỗi từng candidate, không coi đây là xác minh PASS. |
| `BOUNDED_ONLINE_COMPLETE` / `BUDGET_EXPIRED` | Kết thúc phần chạy có giới hạn; không chứng minh discovery đã đầy đủ hay có vulnerability. |
| `NOT_VERIFIED` / `V0_PREREQUISITE_GATE_FAILED` | Chưa có v0 thỏa điều kiện; cần xem seed, method, callback và config. |
| `NOT_VERIFIED` / `WORKER_STOP_FAILED` | Không xác nhận được worker đã dừng; giữ tên container, chặn handoff, trả mã lỗi. Xem `stop_error`. |
| `NOT_VERIFIED` / `CHILD_REPLAY_FAILED` | Replay/Pass 2 không đạt. Dừng worker hiện tại ngay, giữ `replay_result`, artifact và lý do của child, rồi chuyển candidate kế tiếp mà không đợi hết budget. |
| `NOT_VERIFIED` / `CHILD_WORKER_START_FAILED` hoặc `PARENT_WORKER_RESTART_FAILED` | Lỗi khởi động worker; không được ghi thành hoàn thành bình thường. |
| `not_started_budget_expired` | Config có thể đã được tạo hoặc replay, nhưng worker chưa khởi động vì hết ngân sách. |
| `NO_NEW_ZEND_PARAMETER` | Quan sát đó không bổ sung tham số; không chứng minh không còn nhánh chưa khám phá. |
| `ACTION_EXPANSION_SETUP_REQUIRED` | Registration có thật nhưng thiếu direct-HTTP mapping, method/route evidence hoặc prerequisite replay; không tạo request suy đoán. |
| `CALLBACK_REGISTRY_REFRESH_FAILED` | Registry child không nạp lại được vào web container; child candidate bị chặn. |
| `CANDIDATE_BUDGET_EXPIRED` / `CAMPAIGN_BUDGET_EXPIRED` | Batch dừng mở rộng theo cap candidate hoặc wall-clock campaign; timeout từng candidate vẫn độc lập. |
| `VULN_FOUND` | Worker báo điều kiện dừng vulnerability; đối chiếu run, request và artifact để xác nhận phát hiện tương ứng. |

Lỗi hoặc timeout riêng của candidate được ghi `NOT_VERIFIED` và không hủy hàng đợi còn lại. Giới hạn `OnlineMaxCandidates` và `OnlineCampaignTimeoutSeconds` vẫn áp dụng; lỗi đầu vào chung hoặc không ghi được batch state vẫn làm CLI thất bại.

## 6. Final configs

Cuối batch, config được gom vào thư mục phẳng:

```text
fuzzer/output/online-linked/<batch-run-id>/final-configs/fuzzer-config.<hook>.<identity-hash>.json
```

Mỗi candidate lấy phiên bản mới nhất qua replay và Pass 2 (`accepted == total > 0`),
chỉ nhận `fuzzing_ready`. Nếu phiên bản mới bị loại thì xét phiên bản cũ hơn.
File copy nguyên byte, giữ metadata/auth và tham số. Không tạo manifest.
Terminal in đường dẫn, số file và lý do bỏ qua; không có config vẫn là kết quả hợp lệ.
Lỗi ghi xuất trả lỗi, giữ batch-state và file nguồn. Không ghi đè thư mục đã tồn tại.
Nếu ghi lỗi giữa chừng, thư mục có thể chứa một phần config; xem lỗi terminal.
Đây là tổng hợp artifact đã lưu, không chạy lại replay hoặc fuzzing.

## 7. Source map và kiểm chứng

| Thành phần | Source |
| --- | --- |
| Chọn mode | [phuzz.ps1](../../phuzz.ps1) |
| Docker, bootstrap, export seed/registry | [run-wordpress-phuzz.ps1](../../scripts/wordpress/run-wordpress-phuzz.ps1) |
| Vòng phiên bản, handoff, deadline, state | [online_linked_coordinator.py](../../fuzzer/hook_energy/seed_generation/online_linked_coordinator.py) |
| Batch request/Zend evidence reader | [online_linked_evidence.py](../../fuzzer/hook_energy/seed_generation/online_linked_evidence.py) |
| Coordinator online cũ, kiểm tra cấu trúc v0 | [online_config_runner.py](../../fuzzer/hook_energy/seed_generation/online_config_runner.py) |
| Convergence và Pass 2 | [bridge_cli.py](../../fuzzer/hook_energy/seed_generation/zend_runtime/bridge_cli.py) |
| Materialization và exporter | [convergence.py](../../fuzzer/seed_generation/convergence/convergence.py), [config_exporter.py](../../fuzzer/seed_generation/config/config_exporter.py) |
| Root fetch provenance và raw events | [hookphuzz_opcode.c](../../fuzzer/zend_discovery/extension/hookphuzz_opcode.c), [direct-argument fixture](../../fuzzer/tests/fixtures/hookphuzz-direct-argument-fixture.php) |
| CmpLog và mutation | [fuzzer.py](../../fuzzer/fuzzer.py), [hints.py](../../fuzzer/fuzz_guidance/cmplog/hints.py) |

Kiểm tra hồi quy coordinator/runner/wrapper từ `phuzz-main/code`, timeout toàn tiến trình test 180 giây:

```powershell
rtk proxy python -c "import subprocess,sys; r=subprocess.run([sys.executable,'-m','unittest','fuzzer.tests.test_online_linked_coordinator','fuzzer.tests.test_online_config_runner','fuzzer.tests.test_phuzz_wrapper_contract','fuzzer.tests.test_generated_config_runner','fuzzer.tests.test_cmplog','fuzzer.tests.test_cmplog_extension'],timeout=180); sys.exit(r.returncode)"
```

Fresh validation ngày 2026-09-13: focused online-linked/Zend/exporter/probe suite đạt `234 tests OK`; full discovery đạt `542 tests`, còn `2 errors` và `1 skipped`. Hai lỗi full-suite được ghi nguyên văn và không được tự phân loại baseline trong [results report](../../../../docs/superpowers/plans/2026-09-13-online-linked-luna-results.md). Đây là unit/contract và fixture gates; chưa thay thế real-plugin end-to-end run có đủ auth/nonce/selector setup.

Khi nghiệm thu phải báo riêng: đăng ký → request đúng ngữ cảnh → callback executed → tham số/provenance → config tạo được → replay/Pass 2 → worker đã chạy → coverage/CmpLog → vulnerability. Không gộp HTTP 200, callback reachability hoặc test mock thành PASS toàn tuyến.
