# Baseline + Guided Configs Implementation Plan

> **For Luna:** Đọc và áp dụng skill `ponytail:ponytail` mức full khi code; dùng `superpowers:executing-plans` nếu máy đích có skill này. Không tự tạo subagent, commit hoặc push. Thực hiện từng checkpoint và báo evidence. Đây là kế hoạch; chưa triển khai.

**Goal:** Giữ tối đa hai config độc lập cho cùng target: baseline fuzz input ban đầu không dùng CMPLOG mutation; guided giữ giá trị mở điều kiện và fuzz payload bên trong, có CMPLOG mutation.

**Architecture:** Tái sử dụng version, sender, correlation, Pass 2 và worker hiện hữu. Baseline là context đã gate riêng; guided được tạo từ một trial tương quan đạt kiểm tra, không ghi đè baseline. Chạy tuần tự một worker tại một thời điểm; xuất cả hai vào thư mục final-configs phẳng.

**Tech Stack:** Python, unittest, PowerShell wrapper, WordPress/PHP/Zend, Docker.

**Spec:** Tài liệu này chứa đầy đủ contract, không cần lịch sử chat. Mốc tham chiếu mới nhất: `7c0530db15d96643273e2c87bf510e8da7209e2b` (coherent replay); thay mốc `5b33297` của bản đầu. Không yêu cầu máy đích checkout đúng hash nếu đã có logic tương đương; xác minh code và test, không suy đoán từ tên branch.

## Checkpoint 0 — Chuẩn bị máy đích và Ponytail

- [ ] Mở repo máy đích, đọc AGENTS.md áp dụng tại đó và skill Ponytail đã cài. Không dùng đường dẫn `.codex` của máy tác giả. Nếu thiếu Ponytail, báo thiếu skill và dùng các ràng buộc tối thiểu bên dưới; không tuyên bố đã đọc skill chưa có.
- [ ] Chỉ cần chuyển repo có prerequisite coherent replay và tài liệu này. Plan Luna cũ là tài liệu tham khảo tùy chọn, không bắt buộc. Không cần log, ZIP real-plugin, output hoặc đường dẫn Downloads máy cũ để chạy kiểm thử offline.
- [ ] Clone/checkout chỉ chứa dữ liệu đã commit. Nếu có WIP cần mang theo, chuyển bằng patch và sao chép riêng file untracked cần thiết; kiểm tra patch trước áp dụng, không reset/clean để ép khớp. Không chuyển cookie/token/session từ artifacts cũ.
- [ ] Ghi root, HEAD, diff và phiên bản công cụ; thực hiện từ repo root, không hardcode ổ C.

```powershell
$repoRoot = (git rev-parse --show-toplevel).Trim()
Set-Location -LiteralPath $repoRoot
git rev-parse HEAD
git status --short
git diff --stat
python --version
rg -n 'def _verify_replay_input_trials|MAX_REPLAY_INPUT_TRIALS|propose_replay_inputs' phuzz-main/code/fuzzer/hook_energy/seed_generation/online_linked_coordinator.py
rg --files phuzz-main/code/fuzzer/tests | rg 'online_linked_replay_inputs|online_linked_coordinator|online_linked_export|cmplog'
```

- [ ] Prerequisite phải có: `_verify_replay_input_trials`, helper `propose_replay_inputs`, giới hạn 4 trial, exact request/run/callback/transport correlation, Pass 2 và deadline hiện hữu. Chạy suite liên quan trước sửa. Nếu thiếu, báo dependency cụ thể; không tự dựng lại coherent replay trong patch A/B.
- [ ] Nếu test có lỗi sẵn, lưu tên test/trace trước sửa; phân biệt lỗi môi trường với regression. Docker thiếu không cản implementation/offline checks; runtime phải báo chưa xác minh.
- [ ] Ponytail: tái dùng helper/hash/sender/verifier/state hiện có; không thêm thư viện, scheduler class, plugin adapter, config registry hay framework test. Một bool policy, hai role, một worker active là đủ. Chỉ tách helper khi thực sự được dùng chung hoặc cần kiểm tra logic thuần.
- [ ] Giới hạn tối đa hai context và phân bổ thời gian là simplification có trần; dùng comment `ponytail:` ngắn nêu trần, chỉ mở rộng khi có benchmark cần. Không dùng Ponytail để bỏ correlation, gate hoặc xử lý lỗi.
- [ ] Mỗi checkpoint ghi thay đổi/kiểm tra/phần còn thiếu rồi tự tiếp tục khi không có blocker; không xin lại quyền sau mỗi checkpoint. Không tự commit.

## Global Constraints

- Runtime-only: không lấy giá trị điều kiện, endpoint hoặc parameter từ source plugin. Source chỉ dùng viết fixture kiểm thử.
- CMPLOG mode và tập field fuzz là hai quyết định độc lập. Tắt CMPLOG mutation không yêu cầu tắt instrumentation.
- Request có field không chứng minh field được đọc. Read cũng không chứng minh đã tới sink.
- Nonce, action và auth giữ theo quy tắc hiện hữu. Không đổi kiểu JSON, transport, nested path hoặc giá trị false/0/null.
- Không giảm expected_parameters của trial coherent replay để làm gate xanh. Không gom field đọc ở nhiều request thành một baseline.
- Replay, Pass 2 accepted=total>0, nonempty fuzz selectors, hash và correlation phải đạt riêng cho từng config.
- Không reset timeout/campaign deadline; không tăng mặc định max versions/candidates. A/B tiêu thụ version budget bình thường; budget không đủ thì không tạo B.
- Giữ WIP và artifacts cũ. Không sửa generated JSON bằng tay, không thêm manifest/CLI mới, không refactor coordinator ngoài phần cần thiết.
- Giới hạn hai context cho mỗi target identity hiện có, bao gồm callback/method/auth/entrypoint/seed variant. Không dựng cây mọi if/else, không mở nhánh thứ ba.

## Contract và ví dụ

Request A có action=example_action, type=probe, post_id="123". Runtime chỉ đọc type. A giữ post_id dạng chuỗi, fixed như dữ liệu request; không coi post_id là accepted fuzz field.

```python
A = {"role": "baseline", "cmplog_enabled": False,
     "fixed": ["action", "post_id"], "fuzz": ["type"],
     "values": {"action": "example_action", "type": "probe", "post_id": "123"}}
B = {"role": "guided", "cmplog_enabled": True,
     "fixed": ["action", "type"], "fuzz": ["post_id"],
     "values": {"action": "example_action", "type": "post", "post_id": "123"}}
```

Đây là contract logic, không phải schema executable. Nếu A thực sự đọc cả type và post_id, cả hai có thể fuzz ở A. Nếu B không còn field fuzz sau khi khóa selector, giữ replay_only; không publish fuzzing_ready.

Baseline được lấy từ context ban đầu đã gate độc lập, thường là v0. Nếu v0 không đạt, giữ hành vi fail-closed; không cứu bằng cách cắt expected set của trial thất bại. Không đảm bảo lúc nào cũng xuất đủ hai config.

## File map

Mọi đường dẫn bên dưới tương đối với repo root trên máy đích. Tìm theo tên hàm, không theo số dòng của máy tác giả.

- Modify `phuzz-main/code/fuzzer/hook_energy/seed_generation/online_linked_coordinator.py`: `_gate_v0`, `_verify_replay_input_trials`, `_handle_convergence_result`, `_restore_request_values`, `_new_version`, `_start_worker`, `handoff_to_next_worker`, vòng chạy/deadline.
- Modify `phuzz-main/code/fuzzer/hook_energy/seed_generation/online_linked_replay_inputs.py`: giữ provenance chuỗi hint đã dùng để tới trial thắng.
- Modify `phuzz-main/code/fuzzer/fuzzer.py`: đọc policy CMPLOG từ config, fallback environment cho config cũ.
- Modify `phuzz-main/code/fuzzer/hook_energy/seed_generation/online_linked_export.py`: chọn theo role/context thay vì một version cuối mỗi target.
- Read/reuse `phuzz-main/code/fuzzer/seed_generation/config/config_exporter.py`: giữ schema body/query/header/cookie hiện có; ưu tiên truyền fixed/fuzz đúng từ caller, tránh thêm logic role vào exporter chung.
- Tests: `phuzz-main/code/fuzzer/tests/test_online_linked_coordinator.py`, `test_online_linked_replay_inputs.py`, `test_online_linked_export.py`, `test_cmplog.py`, `test_seed_to_config_exporter.py`, `test_phuzz_wrapper_contract.py`.
- Extend runtime fixture `phuzz-main/code/fuzzer/tests/fixtures/hookphuzz-online-discovery-fixture/hookphuzz-online-discovery-fixture.php`: thêm callback độc lập cho A/B, không thay callback cũ. Đọc `test_online_plugin_fixture.py` và `configs/wordpress/hookphuzz-online-discovery-fixture/` trước khi nối harness; không tạo framework hay ZIP installer mới.
- Update `phuzz-main/code/docs/guides/online-linked-flow.md`.

## Checkpoint 1 — Policy sống cùng config

- [ ] Chụp HEAD/status; đọc caller và test helper hiện tại. WIP đã có fuzzer.py và wrapper; không ghi đè.
- [ ] Thêm contract test RED: explicit false thắng environment 1; true bật CMPLOG; config không policy giữ hành vi cũ; giá trị sai kiểu bị từ chối trước worker.
- [ ] Thêm policy vào config trước khi hash/replay; state version lưu context_role và context_id, không suy ra role từ số version.

```python
# Schema mới đề xuất, nằm trong mỗi config executable.
"mutation_policy": {"cmplog_enabled": False}  # A; B dùng True

# Quy tắc parser và launcher phải cùng kết quả.
if "mutation_policy" not in config:
    enabled = os.environ.get("HOOKPHUZZ_CMPLOG", "0") == "1"
else:
    policy = config["mutation_policy"]
    if not isinstance(policy, dict) or type(policy.get("cmplog_enabled")) is not bool:
        raise ValueError("INVALID_MUTATION_POLICY")
    enabled = policy["cmplog_enabled"]
```

- [ ] Launcher truyền 0/1 đúng config; worker dùng policy explicit. Config export chạy lại ngoài coordinator vẫn giữ chế độ.
- [ ] Đọc policy sau khi `self.config` đã nạp, trước ingest/mutation. `__init__` hiện đặt `self.config=None`: không đọc policy tại điểm đó. Missing key mới fallback; explicit null, string "false", 0/1 hoặc thiếu bool trong policy đều là INVALID_MUTATION_POLICY. Giữ default launcher legacy như trước khi config không có policy.
- [ ] Test mutation behavior bằng fixture/stub worker hiện hữu: A không tiêu thụ hint; B áp dụng hint lên fuzz field, không lên fixed field; B hết hint vẫn mutation thường. Không chỉ assert source text.
- [ ] GREEN và báo pass/fail/skip riêng. Chưa đổi instrumentation Zend.

## Checkpoint 2 — Baseline độc lập, bất biến

- [ ] RED: một request chỉ đọc type; A chỉ fuzz type, giữ post_id fixed; request đọc cả hai cho phép cả hai fuzz; nonce không được fuzz.
- [ ] Tại context ban đầu, sử dụng accepted reads tương quan từ gate; candidate chưa đọc không trộn vào accepted set. Giữ nguyên điều kiện gate hiện có.
- [ ] Gắn baseline role/policy trước final hash; khôi phục giá trị bằng `_restore_request_values` từ đúng request. Không để exporter placeholder "fuzz" thay seed quan sát được.
- [ ] Replay chính config sẽ publish. Pass 2 kiểm tra read set baseline riêng; giữ field chưa đọc trong request không đưa nó vào expected read set.
- [ ] Test giữ string "123", số, false, 0, null và transport; thiếu request value phải fail closed như hiện hữu.

```python
# Assertion áp dụng lên config/body section trả bởi fixture coordinator.
self.assertEqual(body["fuzz"], ["type"])
self.assertIn("post_id", body["fixed"])
self.assertEqual(values["type"], "probe")
self.assertEqual(values["post_id"], "123")
self.assertFalse(config["mutation_policy"]["cmplog_enabled"])
```

- [ ] GREEN; lưu hash/bytes A trước trial B để checkpoint sau chứng minh không thay đổi.

## Checkpoint 3 — Trial thắng tạo Guided B

- [ ] RED: hint type=post chỉ tạo proposal; B chưa được publish trước correlated reads và Pass 2. Sai request/run/callback/auth/transport phải bị từ chối.
- [ ] Queue trial giữ provenance của toàn bộ hint đã áp dụng trên đường tới trial thắng, không chỉ hint cuối. Interface queue bổ sung `applied_hints: list[dict]`; result trial trả cùng field.
- [ ] Từ trial thắng, lập locked_parameters theo source/location/path chính xác; khóa tất cả selector thay đổi để mở context. Không khóa theo tên trần gây nhầm query/body hoặc nested field.
- [ ] Mỗi queue item sở hữu bản sao `applied_hints`; t0 bắt đầu `[]`, con dùng `[...parent_hints, current_hint]`. Khi một field đổi nhiều lần, fixed value lấy từ request thắng cuối, provenance giữ đường thử. Không chia sẻ mutable list giữa sibling trials.
- [ ] Locked field phải là field được phép điều chỉnh, có hint tương quan và final read evidence. Không dùng hint để thay action/nonce/auth. Nếu provenance không đủ để phân biệt selector và payload, khóa bảo thủ các field đã điều chỉnh; nếu hết fuzz field thì B replay_only, không tự mở khóa để gate xanh.
- [ ] Tạo B với giá trị request trial thắng; chuyển selector mở nhánh sang fixed; các accepted field còn lại mới được fuzz. Không đổi expected set mà coherent replay hiện đang kiểm tra.
- [ ] Replay/Pass 2 lại config B cuối cùng sau khi đặt fixed/fuzz/policy; publish hash riêng. B cần field mới được đọc hoặc khác biệt thực thi có evidence, không chỉ khác input.
- [ ] Test B khóa type=post, fuzz post_id; nhiều hint khóa đủ selector; B không còn fuzz field thì replay_only. Không nhận trial thứ hai thành context thứ ba.

```python
self.assertEqual(guided_body["fuzz"], ["post_id"])
self.assertIn("type", guided_body["fixed"])
self.assertEqual(guided_values["type"], "post")
self.assertEqual(baseline_path.read_bytes(), baseline_bytes_before)
```

- [ ] GREEN, gồm B thất bại không làm thay đổi accepted parameters/hash/readiness của A.

## Checkpoint 4 — Hai lượt fuzz, một deadline

- [ ] RED với fake clock: không reset deadline, không chạy hai worker cùng lúc, không start B khi parent exit/inspection uncertainty, A/B đều có lượt trong đường thành công đủ budget.
- [ ] Chính sách bản đầu: sau gate A, lấy R là thời gian còn lại tới deadline hiện có. Dành tối đa 20% R cho lượt baseline ban đầu trước discovery, tối đa 50% R tiếp theo cho discovery/replay B; 30% R cuối được dành cho B nếu B đạt. Đây là phân bổ khởi điểm cần đo, không tăng timeout.
- [ ] Cụ thể: t là thời điểm gate A hoàn tất, D=min(candidate deadline,campaign deadline), R=max(0,D-t). Baseline window kết thúc t+0.2R; discovery deadline là t+0.7R. Sender/probe/replay nhận min(deadline hiện có, discovery deadline). Dùng poll loop hiện hữu, không sleep nguyên window. Khi hết cửa sổ discovery, ngừng admission B, không terminate A trước D.
- [ ] A tiếp tục chạy trong discovery. B đạt sớm sau lượt A thì handoff sớm; B thất bại hoặc hết cửa sổ discovery thì A dùng thời gian còn lại. Giới hạn discovery là deadline phụ, không đánh dấu campaign hết hạn trước deadline thật.
- [ ] Giữ kiểm tra parent sống tới khi handoff được xác minh; stop A do handoff hợp lệ không được coi parent failure. Không cần resume A sau khi B đã start.
- [ ] Nếu gate đã tiêu hết budget hoặc lượt fuzz không gửi được mutation, ghi partial/budget reason; không báo đã fuzz cả hai chỉ vì đã start container.
- [ ] GREEN trên fake clock và regression parent-exit/timeout. Ghi actual mutation request count và thời gian từng role.

## Checkpoint 5 — Export cả A/B và giữ tương thích

- [ ] RED: A/B hợp lệ xuất hai file; B invalid chỉ xuất A; A replay_only không được xuất; hash mismatch bị loại; state cũ vẫn chọn latest verified như trước.
- [ ] Với state có role, export tối đa một config hợp lệ mỗi role/context. Giữ `_verified_config` gate; không bỏ kiểm tra run/plugin/hash/Pass 2.
- [ ] Tên phẳng `fuzzer-config.<hook>.<identity-hash>.baseline.json` và `.guided.json`; độc quyền tạo file như hiện hữu. Không manifest, không cây callback/plugin.
- [ ] Semantic context identity gồm target identity, typed request values, fixed/fuzz placement và policy; dùng hash helper hiện có khi phù hợp, không sort mọi array. Request/run ID chỉ là provenance, không là khóa chống trùng context.
- [ ] `context_id` giữ trong state, không nhét vào chính nội dung đang hash để tránh vòng phụ thuộc. `config_hash` vẫn là kiểm tra toàn bộ config executable. Tính policy/giá trị/fixed/fuzz trước hash cuối; không chỉnh bytes sau verification. Không ghi secrets từ input vào tên file.
- [ ] Sửa thống kê: số target được xử lý và số config xuất là hai đại lượng riêng; không dùng targets-count trừ configs-count vì có thể âm.
- [ ] GREEN; guide ghi rõ policy precedence, fixed chưa đồng nghĩa runtime read, và exported chưa đồng nghĩa worker fuzz thành công.

## Checkpoint 6 — Runtime acceptance

- [ ] Fixture có condition dưới đây, đăng ký qua harness fixture đang dùng; tên/value hardcode chỉ ở fixture. Discovery phải học bằng runtime.

```php
$type = $_POST['type'] ?? '';
if ($type === 'post') {
    $post_id = $_POST['post_id'] ?? '';
    if ($post_id === 'deep_target') {
        echo 'deep_reached';
    }
} else {
    echo 'baseline_reached';
}
```

- [ ] Chạy isolated fixture với seed type=probe, post_id="123", đủ version budget cho A/B; wrapper online-linked hiện hữu, timeout 120 giây, không tăng deadline nội bộ. Ghi command thực tế, ZIP/hash, run ID và trạng thái môi trường.
- [ ] Gói/activate fixture bằng cơ chế repo hiện có, không chép đường dẫn container từ máy cũ. Kiểm tra registry có callback mới trước campaign; thiếu callback thì sửa setup fixture, không hardcode vào discovery. Candidate budget phải đủ tới callback kiểm thử; nếu không được schedule, báo riêng thay vì kết luận gate lỗi.
- [ ] Ví dụ wrapper từ `phuzz-main/code` sau khi fixture đã được đóng gói đúng cơ chế repo:

```powershell
python -c 'import subprocess; subprocess.run(["pwsh","-NoProfile","-File","phuzz.ps1","-Mode","online-linked","-PluginSlug","hookphuzz-online-discovery-fixture","-UseZendDiscovery","-OnlineTimeoutSeconds","120","-OnlineMaxVersions","2","-NoFollowLogs"],timeout=600,check=True)'
```

Lệnh trên giới hạn wrapper 600 giây; ngân sách candidate vẫn 120 giây, không phải toàn batch. Đọc help/param tại máy đích trước chạy; nếu wrapper dispatch rồi trả về, tiếp tục poll state/log có deadline, không coi exit 0 là hoàn tất. Khi outer timeout xảy ra, kiểm tra trạng thái container của chính run đó; không để worker thất lạc, không stop container khác.
- [ ] Chứng minh A có mutation thường trên type, B giữ type=post khi mutate post_id; có correlated request thực sự đọc post_id trong B. Comparison deep_target kiểm tra B vẫn dùng CMPLOG; không coi echo/HTTP 200 đơn lẻ là proof.
- [ ] Ca âm: làm trial B không đạt reads hoặc sai correlation; A vẫn giữ và được export nếu gate A đạt. Ca đọc cả hai field trước condition cho phép A fuzz cả hai.
- [ ] So sánh luồng cũ/mới cùng tổng 120 giây, ít nhất 3 lượt mỗi cấu hình nếu đủ môi trường; báo median request count, request đọc post_id, discovery/replay cost và coverage nếu có. Không dùng số config làm chỉ số hiệu quả.
- [ ] Báo riêng test pass/fail/skip, baseline gate/worker, guided gate/worker, final export, budget và artifact paths. Một verdict VERIFIED/PARTIAL/BLOCKED; không có Docker proof thì PARTIAL.

## Lệnh kiểm tra hữu hạn

Từ `phuzz-main/code/fuzzer`, dùng Python đang chạy được suite hiện hữu. Mỗi checkpoint chọn module liên quan; cuối chạy tất cả bên dưới. subprocess timeout là giới hạn cứng, không chỉ timeout chờ output tool.

```powershell
python -c 'import subprocess,sys; names=["test_online_linked_coordinator.py","test_online_linked_replay_inputs.py","test_online_linked_export.py","test_cmplog.py","test_seed_to_config_exporter.py","test_phuzz_wrapper_contract.py"]; [subprocess.run([sys.executable,"-m","unittest","discover","-s","tests","-p",name],timeout=300,check=True) for name in names]'
git diff --check
```

## Handoff

- [ ] Coherent replay hiện chọn một trial thắng; kế hoạch này giữ baseline riêng và thêm guided, nhưng không nới trial verification. Không cần plan cũ để thực thi contract này.
- [ ] Sau mỗi checkpoint, ghi thay đổi, evidence, phần còn thiếu rồi tiếp tục nếu không có blocker. Không commit trừ khi người dùng yêu cầu.
- [ ] Self-review: schema policy thống nhất parser/launcher/export; không mất A khi B fail; deadline không reset; budget versions không vượt; final export không gọi là fuzzing PASS.

## Checkpoint 7 — Viết docs cuối cùng và bàn giao

Chỉ cập nhật docs theo implementation cuối cùng sau kiểm tra; không ghi tính năng chưa chạy thành hiện trạng. Dùng đúng `phuzz-main/code/docs/guides/online-linked-flow.md`, không tạo guide thứ hai trùng nội dung.

- [ ] Thêm mục Baseline/Guided: bảng role, CMPLOG mode, fixed/fuzz và giới hạn hai context. Giải thích field chưa đọc có thể giữ fixed để bảo toàn request nhưng không được công nhận fuzzable.
- [ ] Thêm sơ đồ request ban đầu → gate A → mutation A → trial B → replay/Pass 2 → B hoặc tiếp tục A. Ghi rõ handoff dừng A, giữ file A và evidence, không chạy hai worker cùng lúc.
- [ ] Đưa hai config executable đã sinh và xác minh vào ví dụ docs (ẩn token/cookie). Ghi endpoint/method là ví dụ fixture, không dữ liệu suy đoán cho plugin thật. Nếu chưa có runtime, dùng snippet minh họa và gắn nhãn chưa chạy; không bịa config hoàn chỉnh.
- [ ] Mô tả precedence policy explicit → environment fallback, lỗi invalid policy, config legacy, chạy lại final config, giới hạn phiên bản và lịch 20/50/30 đúng implementation thực tế.
- [ ] Hướng dẫn đọc output bằng đường dẫn tương đối: batch-state → candidate state → versions → request/Zend/replay → final-configs. Tên thư mục thực tế lấy từ run; không tạo schema artifact khác chỉ để khớp docs.
- [ ] Bảng xử lý lỗi: v0 gate fail; B thiếu read; B no fuzz fields; wrong correlation; parent exit/inspection timeout; budget hết; hash mismatch; callback chưa được schedule. Với mỗi lỗi ghi có export A/B hay không và evidence cần xem; dùng reason code thật trong code, không tự đặt code trong docs.
- [ ] Ghi command offline/runtime thực tế đã chạy, công cụ và timeout. Tách số pass/fail/skip, request mutation, gate, export và benchmark. Không có runtime thì nói rõ phần nào chỉ được offline test.
- [ ] Rà diff chỉ chứa file cần thiết; cập nhật checkbox trong plan theo evidence, không tick runtime chưa chạy. Không commit/push.

Mẫu báo cáo cuối Luna phải điền bằng số đo thật, không giữ nguyên các ô mô tả:

| Hạng mục | Kết quả cần ghi |
| --- | --- |
| Code | HEAD gốc, file sửa, thống kê diff, WIP giữ lại |
| Offline | Tổng/pass/fail/skip từng suite, lý do skip |
| Baseline A | Config/hash, request/run ID, Pass 2, mutation count, CMPLOG off |
| Guided B | Config/hash, selector fixed, read evidence, Pass 2, mutation count, CMPLOG on |
| Failure path | B fail có giữ nguyên A không; evidence test/run |
| Export | Số file, đường dẫn, lý do target/config bị loại |
| Runtime | Fixture/plugin hash, command, deadline, thời gian, artifact paths |
| Docs | Link guide đã cập nhật và mục thêm/sửa |
| Verdict | VERIFIED khi đủ acceptance; PARTIAL khi thiếu runtime/benchmark bắt buộc; BLOCKED khi prerequisite ngăn tiếp tục |

### Prompt giao Luna trên máy đích

```text
Đọc docs/superpowers/plans/2026-09-16-baseline-guided-configs.md trong repo hiện tại và triển khai đầy đủ checkpoint 0–7. Dùng plugin Ponytail, skill ponytail:ponytail mức full: tái dùng code hiện hữu, không thêm abstraction/dependency ngoài yêu cầu. Nếu skill chưa cài thì báo và áp dụng các quy tắc Ponytail đã ghi trong plan.

Tìm repo root và kiểm tra HEAD/WIP trước sửa. Không phụ thuộc lịch sử chat, đường dẫn máy cũ hay artifacts máy cũ. Xác minh prerequisite coherent replay bằng code/test. Mục tiêu: A fuzz field đã đọc bằng mutation thường; B giữ selector mở nhánh, fuzz payload có CMPLOG; evidence/gate/hash riêng; giữ cả hai final config nếu hợp lệ; một worker active và deadline chung.

Thực hiện từng checkpoint, báo kiểm tra rồi tiếp tục. Không nới gate, không tự commit/push, không xóa WIP. Chạy offline tests hữu hạn và runtime fixture khi môi trường cho phép. Nếu runtime không khả dụng, hoàn thành phần độc lập, ghi rõ phần chưa kiểm chứng. Cuối cùng cập nhật phuzz-main/code/docs/guides/online-linked-flow.md theo checkpoint 7 và báo một verdict VERIFIED/PARTIAL/BLOCKED cùng evidence paths.
```
