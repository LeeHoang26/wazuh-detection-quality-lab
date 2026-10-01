# Phương pháp đo

## Mục tiêu

Lab dùng cùng một bộ dữ liệu nhỏ để kiểm tra ba câu hỏi:

1. Rule có bắt được mẫu đáng ngờ không?
2. Rule có báo nhầm trên hoạt động bình thường không?
3. Khi dữ liệu thiếu hoặc có process hợp lệ chạm canary, hệ thống có tránh quyết định quá mạnh không?

## Bộ dữ liệu 15 case

Bộ test gồm 5 positive, 5 negative và 5 edge case. Mỗi case có ID cố định, event ID, field đầu vào và expected outcome. Nhờ vậy anh có thể chạy lại sau khi sửa rule mà không đổi tiêu chuẩn giữa các lần đo.

Các fixture là dữ liệu mô phỏng đã làm sạch. Chúng không phải log lấy từ một nạn nhân thật và không chứa credential thật.

## Cách chấm

Matcher đọc field trong fixture rồi trả về rule ID dự đoán. Kết quả được so với `expected`:

- TP: dự đoán đúng alert và đúng rule.
- FP: dự đoán alert trong negative case.
- FN: không dự đoán alert trong positive case.
- TN: không dự đoán alert trong negative case.
- WRONG_RULE: có alert nhưng match nhầm rule.

Precision được tính bằng `TP / (TP + FP)`. Recall được tính bằng `TP / (TP + FN)`. Chỉ positive và negative được đưa vào hai mẫu số này.

Edge case được báo riêng vì nó thường cần `manual_review`, không nên ép thành một con số precision/recall đơn giản.

## Baseline và safety

Baseline mô phỏng các điều kiện field của Wazuh rules hiện tại. Safety profile thêm một lớp chính sách:

- Thiếu identity hoặc source context thì hạ mức chắc chắn.
- Thiếu command line thì không nên tự động cô lập ngay.
- Process bảo mật hợp lệ chạm canary thì không nên suy ra ransomware ngay.

Safety profile là mô hình kiểm thử chất lượng, không phải production policy hoàn chỉnh.

## Actual Wazuh

Khi có file trong `reports/actual/`, runner so sánh thêm rule ID thật từ `wazuh-logtest`. File actual không được commit vì có thể chứa output môi trường cá nhân; `.gitignore` đã bỏ qua thư mục đó.

Offline result cho biết logic kiểm thử local hoạt động thế nào. Actual result cho biết Wazuh Manager trong VMware thực sự decode và match thế nào. Hai kết quả có thể khác, và sự khác biệt đó chính là dữ liệu tuning có ích.
