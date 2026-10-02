# Giới hạn của lab

- Offline matcher là Python nhỏ để kiểm tra logic field; nó không phải Wazuh decoder hoặc Wazuh Manager.
- Bộ dữ liệu chỉ có 17 case được chọn thủ công, không đại diện cho toàn bộ Windows và Active Directory.
- Điều kiện loại shortcut chỉ áp dụng tên và thư mục Recent cụ thể trong case study. Chưa kiểm chứng trên Wazuh Manager và không có nghĩa mọi shortcut hoặc process Explorer đều hợp lệ.
- Precision và recall trong report là kết quả của corpus lab, không phải chỉ số production.
- Wazuh thật có thể decode field khác với giả định offline; cần chạy `wazuh-logtest` để xác nhận.
- JSON fixture dán vào Ruleset Test được decoder `json` đọc. Rule Windows của Manager cần decoder `windows_eventchannel`; vì vậy chỉ có Phase 2 không được chấm là rule bỏ sót.
- Alert lịch sử trong Discover chứng minh rule đã từng chạy, nhưng không phải actual result của fixture tương tự. Không điền `reports/actual/` cho fixture nếu chính fixture chưa được gửi qua Agent.
- Rule `100100` trên Manager quan sát ngày 2026-10-02 là level 8; file baseline trong repo là snapshot lịch sử level 12. Không coi hai bản là đồng nhất.
- Rule `100200` chưa được nạp trên Manager khi kiểm tra, trong khi `ossec.conf` vẫn có Active Response gọi `canary-triage.cmd`. Script đó có thể suspend và terminate process lấy từ Sysmon Event 11. Cần sửa điều kiện và response trước khi bật rule canary.
- Live validation later loaded the detection-only candidate with Active Response disabled. It matched a real TXT Event 11 from an Explorer copy operation; this proves telemetry and rule coverage, not malicious behavior or a safe automated response.
- Repo không tự gửi Telegram, không disable account, không block IP, không kill process và không cô lập máy.
- Tên action trong fixture là nhãn thảo luận response, không phải lệnh được thực thi.
- Edge case không được trộn vào precision/recall vì mục tiêu của nó là đo context và safety decision.
- Việc sao chép rule vào Wazuh Manager phải được làm trong lab cô lập và phải kiểm tra rule ID trùng trước khi restart.
- Dữ liệu actual từ môi trường cá nhân không nên commit nếu có username, IP nội bộ hoặc thông tin nhạy cảm.
