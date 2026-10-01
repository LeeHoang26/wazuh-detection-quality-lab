# Giới hạn của lab

- Offline matcher là Python nhỏ để kiểm tra logic field; nó không phải Wazuh decoder hoặc Wazuh Manager.
- Bộ dữ liệu chỉ có 15 case được chọn thủ công, không đại diện cho toàn bộ Windows và Active Directory.
- Precision và recall trong report là kết quả của corpus lab, không phải chỉ số production.
- Wazuh thật có thể decode field khác với giả định offline; cần chạy `wazuh-logtest` để xác nhận.
- Repo không tự gửi Telegram, không disable account, không block IP, không kill process và không cô lập máy.
- Tên action trong fixture là nhãn thảo luận response, không phải lệnh được thực thi.
- Edge case không được trộn vào precision/recall vì mục tiêu của nó là đo context và safety decision.
- Việc sao chép rule vào Wazuh Manager phải được làm trong lab cô lập và phải kiểm tra rule ID trùng trước khi restart.
- Dữ liệu actual từ môi trường cá nhân không nên commit nếu có username, IP nội bộ hoặc thông tin nhạy cảm.
