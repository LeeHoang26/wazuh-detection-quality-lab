# Hướng dẫn làm lab trên VMware

Tài liệu này viết cho người mới. Anh cứ làm đúng thứ tự, chạy từng lệnh một, không cần tự đoán bước tiếp theo.

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
| `SIEM-SRV` - Ubuntu + Wazuh Manager | Nhận log, chứa rule, chạy `wazuh-logtest` | Bắt buộc khi test thật |
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

## 4. Mở máy ảo theo thứ tự

### 4.1. Chạy offline trước, không cần VMware

Đây là bước an toàn nhất và cũng là bước bắt buộc đầu tiên.

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
FIXTURE VALIDATION PASSED: 15 cases
positive=5 negative=5 edge=5
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

## 5. Cài rule baseline lên Wazuh Manager

Chỉ làm bước này nếu rule `100100`, `100101`, `100102`, `100200`, `100300` chưa có trên `SIEM-SRV`.

Trước tiên kiểm tra:

```bash
sudo grep -R -n 'id="100100"\|id="100101"\|id="100102"\|id="100200"\|id="100300"' /var/ossec/etc/rules/
```

Nếu đã thấy các rule này trong output, không dán thêm lần nữa. Rule trùng ID có thể làm Wazuh báo lỗi.

Nếu chưa có, mở file rule local:

```bash
sudo cp /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml.bak
sudo nano /var/ossec/etc/rules/local_rules.xml
```

Mở file `detections/wazuh/baseline-rules.xml` trên máy thật, copy nội dung các block `<group>...</group>` rồi dán vào cuối `local_rules.xml`. Không dán thêm một XML header thứ hai.

Trong `nano`:

- `Ctrl+O`, Enter để lưu.
- `Ctrl+X` để thoát.

Kiểm tra cấu hình trước khi restart:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
```

Nếu không có lỗi nghiêm trọng, restart:

```bash
sudo systemctl restart wazuh-manager
```

Sau đó kiểm tra lại:

```bash
sudo systemctl is-active wazuh-manager
```

## 6. Đưa fixture vào `wazuh-logtest`

### 6.1. Tạo file event để dán

Trên máy thật, trong thư mục repo chạy lại:

```powershell
python scripts\export_logtest_events.py
```

Mỗi file trong `reports\logtest-inputs\` chỉ chứa phần event Wazuh cần đọc, không chứa metadata của fixture.

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

Dán một event vào cửa sổ Terminal rồi nhấn Enter. Chỉ dán một event mỗi lần. Wazuh sẽ in ra decoder, rule ID và level nếu rule khớp.

Ví dụ với `POS-100100-001`, kết quả mong đợi là rule `100100`. Ghi lại ba thông tin:

```text
case_id: POS-100100-001
alert: true
rule_id: 100100
level: 12
```

Để thoát `wazuh-logtest`, nhấn `Ctrl+C`.

Làm tương tự cho cả 15 file nếu muốn có bộ đo đầy đủ. Tối thiểu nên test một positive, một negative và một edge case để hiểu ba loại kết quả.

## 7. Ghi kết quả Wazuh thật vào report

Quay lại PowerShell tại thư mục repo. Ví dụ Wazuh trả về alert rule `100100` cho case đầu tiên:

```powershell
python scripts\record_actual.py --case-id POS-100100-001 --alert --rule-id 100100 --level 12 --notes 'Matched in wazuh-logtest'
```

Ví dụ Wazuh không tạo alert cho case bình thường:

```powershell
python scripts\record_actual.py --case-id NEG-100100-001 --no-alert --notes 'No matching rule in wazuh-logtest'
```

Lặp lại cho từng case đã test. Sau đó chạy report có so sánh kết quả thật:

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

### Wazuh không trả về rule 100100...

Kiểm tra lần lượt:

1. Rule đã có trong `/var/ossec/etc/rules/` chưa.
2. ID có bị trùng không.
3. `wazuh-analysisd -t` có báo lỗi không.
4. Manager đã restart sau khi sửa rule chưa.
5. Event dán vào có đúng một dòng JSON và đúng field không.

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
- [ ] Validator báo 15 cases.
- [ ] Có baseline report.
- [ ] Có safety report.
- [ ] Hiểu positive, negative và edge case.
- [ ] `SIEM-SRV` chạy Wazuh Manager.
- [ ] Đã kiểm tra rule không bị trùng.
- [ ] Đã chạy ít nhất 3 event qua `wazuh-logtest`.
- [ ] Đã ghi actual result cho các case đã test.
- [ ] Đã đọc cột Offline và Actual trong report.

## 12. Cách nói khi phỏng vấn

Anh có thể trình bày ngắn như sau:

> “I reused my AD and Wazuh detection hypotheses and built a dependency-free regression harness. It tests positive, negative, and edge-case telemetry, reports TP, FP, FN, TN, precision and recall, and compares offline predictions with real `wazuh-logtest` results. I also separated manual review from destructive response when context is incomplete or a known-good process touches a canary file.”

Điểm quan trọng là nói đúng những gì anh đã chạy và có report chứng minh.
