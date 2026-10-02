# Hướng dẫn làm lab trên VMware

Tài liệu này viết cho người mới. Anh cứ làm đúng thứ tự, chạy từng lệnh một, không cần tự đoán bước tiếp theo.

## Đọc trước khi bắt đầu

Bản hướng dẫn chính là file Word riêng được giao bên ngoài repository. Bản Word giải thích theo kiểu thực hành thủ công: bấm ở đâu, nhìn field nào, cần chụp ảnh gì và xử lý khi kết quả chưa đúng. File Word không được đưa vào repo portfolio.

Không bắt đầu bằng Python. Thứ tự nên làm là:

1. Mở Word manual và làm phần snapshot, mạng VMware, Event Viewer.
2. Kiểm tra Wazuh Manager, Agent và Sysmon.
3. Xem alert thật trong Wazuh Discover, đối chiếu Event ID, field và rule ID.
4. Dùng Ruleset Test để xem JSON fixture được decode ra field nào; không coi Phase 2 là rule đã match.
5. Chỉ sau đó mới dùng Python để tạo report và đối chiếu kết quả.

File JSON và report có sẵn trong repo chỉ là dữ liệu chuẩn bị. Chúng không thay thế screenshot và kết quả Wazuh thật.

## 1. Repo này dùng để làm gì?

Repo này không phải một hệ thống tấn công và cũng không phải một SOAR tự động xử lý máy tính. Nó trả lời một câu hỏi trong công việc SOC:

> Rule Wazuh có bắt đúng log đáng ngờ, bỏ qua log bình thường và xử lý an toàn khi log bị thiếu thông tin hay không?

Repo flagship `ad-threat-detection-and-response-lab` trình diễn phát hiện và response. Repo này kiểm tra chất lượng của các rule đó bằng ba nhóm log:

- `positive`: log đáng lẽ phải tạo alert.
- `negative`: log bình thường, đáng lẽ không tạo alert.
- `edge-cases`: log gần giống tấn công nhưng thiếu context hoặc có hành vi hợp lệ đặc biệt.

## 2. Cần những máy ảo nào?

Anh có thể chạy phần offline mà không mở VMware. Muốn kiểm tra thật bằng Wazuh thì dùng lại lab cũ:

| Máy ảo | Vai trò | Có bắt buộc không? |
| --- | --- | --- |
| `SIEM-SRV` - Ubuntu + Wazuh Manager | Nhận log, chứa rule, chạy Dashboard/Ruleset Test | Bắt buộc khi test thật |
| `DC01` - Windows Server + Active Directory | Tạo Windows Security Event 4768, 4769, 4662 | Cần cho bài AD thật |
| `WK01` - Windows + Sysmon + Wazuh Agent | Tạo Sysmon Event 1 và 11 | Cần cho bài process/file thật |
| `KALI` - Kali Linux | Máy mô phỏng nguồn tấn công | Không bắt buộc; chỉ mở khi cần tái tạo hoạt động |

Điểm quan trọng: các fixture JSON trong repo đã được làm sạch và có thể kiểm tra offline. Anh không cần chạy tấn công thật để chạy regression report.

## 3. Chuẩn bị trước khi mở máy ảo

### 3.1. Tạo snapshot

Tắt máy ảo nếu cần, sau đó trong VMware chọn từng VM rồi tạo snapshot với tên dễ nhớ, ví dụ:

```text
Before-detection-quality-lab
```

Snapshot là điểm quay lại. Nếu cấu hình rule sai, anh có thể quay về trạng thái trước khi chỉnh sửa.

### 3.2. Kiểm tra mạng VMware

Các VM phải nằm trong cùng mạng lab. Với bài học an toàn, ưu tiên `Host-only` hoặc một `Custom VMnet` riêng. Không dùng `Bridged` nếu không thật sự cần, vì Bridged đưa máy ảo ra mạng thật của gia đình/trường.

Trong VMware:

1. Mở `VM > Settings > Network Adapter`.
2. Chọn cùng một mạng lab cho `SIEM-SRV`, `DC01`, `WK01` và `KALI`.
3. Không đổi IP nếu lab cũ đang chạy ổn.
4. Ghi lại IP của `SIEM-SRV`, vì Wazuh Agent cần biết địa chỉ Manager.

Trên Ubuntu `SIEM-SRV`, mở Terminal và chạy:

```bash
ip addr
```

Tìm địa chỉ IPv4 của card mạng lab. Trên Windows `DC01` hoặc `WK01`, mở PowerShell:

```powershell
ipconfig
```

Nếu các máy không ping được nhau, dừng ở đây và sửa mạng trước. Không nên tiếp tục cấu hình Wazuh khi nền mạng chưa thông.

## 4. Mở và kiểm tra máy ảo theo thứ tự

### 4.1. Python offline là phần phụ, chạy sau khi đã hiểu thủ công

Phần này không bắt buộc để hiểu Wazuh. Chạy sau khi anh đã xem Event Viewer và alert thật trong Discover. Đây là cách tạo lại fixture và report bằng máy tính, không phải kết quả Wazuh thật.

Mở PowerShell trên máy thật, chạy:

```powershell
Set-Location 'E:\LABS FOR FRESHER\soc-detection-quality-and-regression-lab'
```

Nếu Python đã cài, chạy từng lệnh:

```powershell
python scripts\generate_fixtures.py
```

```powershell
python scripts\validate_fixtures.py
```

```powershell
python scripts\export_logtest_events.py
```

```powershell
python scripts\run_regression.py --profile baseline
```

```powershell
python scripts\run_regression.py --profile safety
```

Kết quả đúng sẽ có dòng gần giống:

```text
FIXTURE VALIDATION PASSED: 17 cases
positive=5 negative=7 edge=5
```

Các file quan trọng được tạo ra:

```text
reports\baseline-report.md
reports\safety-report.md
reports\baseline-results.json
reports\safety-results.json
reports\logtest-inputs\
```

Mở report bằng Notepad:

```powershell
notepad reports\baseline-report.md
```

### 4.2. Mở VMware để kiểm tra Wazuh thật

Nếu chỉ cần hoàn thành report offline, anh có thể dừng sau bước 4.1. Nếu muốn chứng minh rule thật sự chạy trên Wazuh, mở theo thứ tự này:

1. `SIEM-SRV` trước.
2. `DC01` tiếp theo.
3. `WK01` tiếp theo.
4. `KALI` chỉ mở khi cần, không bắt buộc.

Trên `SIEM-SRV`, kiểm tra Wazuh Manager:

```bash
sudo systemctl is-active wazuh-manager
```

Nếu kết quả là `active` thì Manager đang chạy. Có thể kiểm tra thêm:

```bash
sudo /var/ossec/bin/wazuh-control status
```

Trên `WK01`, kiểm tra Wazuh Agent và Sysmon bằng PowerShell chạy với quyền Administrator:

```powershell
Get-Service WazuhSvc
```

```powershell
Get-Service Sysmon*
```

Nếu service là `Running` thì máy đang gửi telemetry theo cấu hình cũ. Không cần cài lại nếu lab flagship đã hoạt động.

## 5. Đối chiếu rule đang chạy

Trên Wazuh Dashboard vào `Server management > Rules`, tìm từng ID `100100`, `100101`, `100102`, `100200`, `100300` và ghi lại level, mô tả, tên file. Chỉ đọc, không bấm Save.

Ngày 2026-10-02, Manager đã có `100100` level 8, `100101`, `100102`, `100300`, nhưng chưa có `100200`. File `detections/wazuh/baseline-rules.xml` trong repo là snapshot lịch sử, không trùng hoàn toàn với Manager hiện tại.

Đặc biệt, `ossec.conf` đã có Active Response gắn ID `100200` với `canary-triage.cmd`; script PowerShell phía sau có thể suspend và terminate process dựa trên Sysmon Event 11. Một file `.lnk` hợp lệ do Explorer tạo cũng chứa tên canary. Vì vậy không thêm rule `100200` trong bước này.

## 6. Kiểm tra decoder và rule đúng cách

### 6.1. Tạo file event để dán

Trên máy thật, trong thư mục repo chạy lại:

```powershell
python scripts\export_logtest_events.py
```

Mỗi file trong `reports\logtest-inputs\` chỉ chứa phần JSON để kiểm tra field decoder, không chứa metadata của fixture. File này không mang metadata EventChannel của Wazuh Agent.

Ví dụ xem một event:

```powershell
Get-Content reports\logtest-inputs\POS-100100-001.json
```

Copy nguyên một dòng JSON được in ra.

### 6.2. Chạy logtest trên SIEM-SRV

Trên Ubuntu `SIEM-SRV`:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Dán một event vào cửa sổ Terminal rồi nhấn Enter. Chỉ dán một event mỗi lần. Với fixture JSON tối giản hiện tại, kết quả có thể dừng ở `Phase 2: json` và không có Phase 3. Đó là kết quả decoder, **không phải false negative** của rule `100100`.

Lý do: rule Windows của Wazuh yêu cầu nhóm `windows`; base rule của nhóm này dựa trên decoder `windows_eventchannel`. JSON dán tay được decoder `json` đọc, nên không đi cùng đường xử lý với event Windows do Agent gửi thật.

Để xác nhận rule đang chạy, mở Wazuh Dashboard > Explore > Discover, chọn `wazuh-alerts-*`, chọn khoảng thời gian chứa event và tìm `rule.id: 100101`, `rule.id: 100102` hoặc `rule.id: 100300`. Mở một alert và đọc Event ID, field, agent, rule ID, level. Với rule không có alert, ghi `chưa quan sát được alert trong khoảng thời gian này`; không tự ghi `no alert` cho một fixture chưa đi qua Agent.

Để thoát `wazuh-logtest`, nhấn `Ctrl+C`.

Các fixture vẫn có ích cho offline regression. Muốn tính actual TP/FP/FN/TN cho đúng 17 case, phải đưa chính các event đó qua đường Windows EventChannel và xác nhận kết quả từng case. Không dùng alert lịch sử của một event tương tự để thay cho fixture.

## 7. Ghi kết quả Wazuh thật vào report

Chỉ làm phần này sau khi chính fixture đã được phát qua Agent và được Wazuh xử lý. Ví dụ nếu rule `100100` của Manager hiện tại trả về level 8 cho case đầu tiên:

```powershell
python scripts\record_actual.py --case-id POS-100100-001 --alert --rule-id 100100 --level 8 --notes 'Verified with agent-collected event'
```

Ví dụ Wazuh không tạo alert cho chính case bình thường đã được gửi qua Agent:

```powershell
python scripts\record_actual.py --case-id NEG-100100-001 --no-alert --notes 'Verified with agent-collected event'
```

Chỉ dùng các lệnh trên nếu **chính fixture đó** đã đi qua Windows Agent và được kiểm tra trong Discover. Alert lịch sử có field tương tự không được gán vào case ID này. Sau đó chạy report có so sánh kết quả thật:

```powershell
python scripts\run_regression.py --profile baseline --actual-dir reports\actual
```

Mở report:

```powershell
notepad reports\baseline-report.md
```

Trong bảng report:

- `Offline`: matcher Python đoán gì từ fixture.
- `Actual`: Wazuh thật trả về rule nào.
- `Offline result`: kết quả của matcher local.
- `Actual result`: kết quả so với Wazuh thật.
- Dấu `-`: chưa có file actual cho case đó, không có nghĩa là Wazuh không alert.

## 8. Đọc TP, FP, FN, TN thật dễ hiểu

Chỉ dùng các case `positive` và `negative` để tính precision/recall. Edge case được tách riêng vì mục tiêu của nó là kiểm tra thiếu context và quyết định an toàn.

- `TP`: log xấu, rule bắt được. Tốt.
- `FP`: log bình thường nhưng rule bắt nhầm. Gây mệt cho analyst.
- `FN`: log xấu nhưng rule bỏ sót. Nguy hiểm.
- `TN`: log bình thường và rule bỏ qua. Tốt.
- `Precision`: trong tất cả alert, có bao nhiêu alert thật sự đáng chú ý.
- `Recall`: trong tất cả log xấu, rule bắt được bao nhiêu.

Đừng ghi vào CV rằng `100%` trên report nhỏ này nghĩa là hệ thống production đạt 100%. Hãy nói đúng: “I built a curated regression corpus and measured detection behavior across positive, negative, and edge cases.”

## 9. Baseline và Safety profile khác nhau thế nào?

Chạy baseline:

```powershell
python scripts\run_regression.py --profile baseline
```

Baseline mô phỏng điều kiện field hiện tại của rule Wazuh. Ví dụ chỉ cần event 4769 có RC4 `0x17` là rule Kerberoasting có thể match.

Chạy safety:

```powershell
python scripts\run_regression.py --profile safety
```

Safety thêm các kiểm tra thận trọng:

- Thiếu username hoặc source IP trong Kerberos thì chuyển sang `manual_review`.
- Thiếu command line trong remote shell thì chuyển sang `manual_review`.
- Defender hoặc SearchIndexer chạm canary thì không suy ra ransomware ngay.

Safety profile là mô hình thí nghiệm để thảo luận tuning. Nó không phải file rule production thay thế ngay cho Wazuh.

## 10. Các lỗi thường gặp

### `python is not recognized`

Thử Python Launcher:

```powershell
py scripts\validate_fixtures.py
```

Nếu cả hai đều không chạy, cài Python 3 và bật tùy chọn `Add python.exe to PATH`.

### `No such file or directory` khi chạy Python

Anh đang đứng sai thư mục. Chạy:

```powershell
Set-Location 'E:\LABS FOR FRESHER\soc-detection-quality-and-regression-lab'
```

Rồi chạy lại lệnh.

### Ruleset Test chỉ hiện Phase 2

Nếu decoder là `json`, đây là kết quả kiểm tra field. Rule Windows cần decoder `windows_eventchannel`, nên không có Phase 3 không chứng minh rule bỏ sót. Dùng alert thật trong Discover để xác nhận rule đang chạy.

### Wazuh không trả về rule 100100...

Kiểm tra lần lượt:

1. Rule đã có trong `/var/ossec/etc/rules/` chưa.
2. ID có bị trùng không.
3. Alert thật trong Discover có đúng Event ID và field không.
4. Ruleset Test có đang dùng decoder `json` thay vì `windows_eventchannel` không.

### Wazuh alert nhưng khác rule mong đợi

Ghi rule thật vào `reports/actual/`. Đây là dữ liệu có ích: nó cho thấy rule đang bị overlap hoặc event đang được decode khác với giả định. Không sửa số liệu để cho đẹp.

### `FIXTURE VALIDATION FAILED`

Không tự sửa các file fixture trước khi đọc dòng lỗi. Chạy lại:

```powershell
python scripts\generate_fixtures.py
python scripts\validate_fixtures.py
```

## 11. Checklist hoàn thành

- [ ] Chạy được generator.
- [ ] Validator báo 17 cases.
- [ ] Có baseline report.
- [ ] Có safety report.
- [ ] Hiểu positive, negative và edge case.
- [ ] `SIEM-SRV` chạy Wazuh Manager.
- [ ] Đã kiểm tra rule không bị trùng.
- [ ] Đã xem decoder của một fixture trong Ruleset Test và hiểu vì sao Phase 3 có thể vắng mặt.
- [ ] Đã xem ít nhất một alert thật của Agent trong Discover.
- [ ] Chỉ ghi actual result cho fixture đã được đưa qua Agent thật.
- [ ] Đã đọc cột Offline và Actual trong report.

## 12. Cách nói khi phỏng vấn

Anh có thể trình bày ngắn như sau:

> “I reused my AD and Wazuh detection hypotheses and built a dependency-free regression harness. It tests positive, negative, and edge-case telemetry, reports TP, FP, FN, TN, precision and recall, and compares offline predictions with real Windows EventChannel alerts in Wazuh Discover. I also separated manual review from destructive response when context is incomplete or a known-good process touches a canary file.”

Điểm quan trọng là nói đúng những gì anh đã chạy và có report chứng minh.
