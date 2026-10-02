# Tuning notes

## Kerberoasting

Một request service ticket dùng RC4 là tín hiệu đáng chú ý nhưng chưa đủ mạnh để kết luận. Có ứng dụng cũ vẫn dùng RC4. Nên bổ sung tần suất request, danh sách service account, username, source IP và lịch sử hành vi trước khi tự động response.

Nếu thiếu `targetUserName` hoặc `ipAddress`, alert vẫn có thể có giá trị để điều tra nhưng nên chuyển `manual_review` thay vì hành động mạnh.

## AS-REP Roasting

`preAuthType=0` cộng với encryption type đáng chú ý giúp nhận diện mẫu AS-REP. Tuy nhiên việc disable account hoặc đổi password phải đi qua IAM playbook đã được phê duyệt. Alert detection không tự nó là quyền cho phép khóa tài khoản.

## DCSync

Replication GUID là context quan trọng hơn một event 4662 chung chung. Production cần biết identity đó có phải Domain Controller hoặc service account được phép replication không. Vì vậy cần allowlist có kiểm soát và điều tra subject account.

Trong lab, Manager đã tạo alert `100102` level 14 cho Event 4662 có replication GUID nhưng `subjectUserName=DC01$`, `subjectUserSid=S-1-5-18`. Đây là ứng viên false positive cần xác minh với hoạt động replication hợp lệ của DC; chỉ thấy GUID không đủ để gọi là DCSync trái phép.

Safety candidate giữ nguyên alert `100102` và gắn quyết định `manual_review` cho tổ hợp mô phỏng: tài khoản `DC01$`, domain `LAB`, SID `S-1-5-18`, máy ghi log `DC01` hoặc `DC01.lab.local`. Đây là điều kiện nhận diện một mẫu cần xem xét, không phải danh sách tài khoản được tin cậy. Thiếu hoặc khác một field thì vẫn giữ quyết định `investigate`. Không bỏ qua mọi tài khoản có đuôi `$`.

Mẫu negative giả định replication hợp lệ vẫn bị chấm `FP` ở cả baseline và safety vì alert còn nguyên. Cột Decision chỉ giúp analyst biết cần kiểm tra gì; nó không làm precision/recall tăng. Năm alert thật từ `DC01$` vẫn là các trường hợp cần xác minh, chưa đủ bằng chứng để gán nhãn hợp lệ cho từng alert.

## WMI và WinRM lateral movement

Quan hệ parent-child như `WmiPrvSE.exe -> cmd.exe` hoặc `wsmprovhost.exe -> powershell.exe` giúp phát hiện remote shell. Sysmon Event 1 thường không cho biết đầy đủ source IP. Cần correlate với Security Event 4624 và các event mạng để biết máy nguồn.

Nếu command line bị thiếu, vẫn giữ alert để analyst xem nhưng không nên tự động isolate chỉ từ một process lineage chưa đủ context.

## Canary ransomware

Canary filename bị chạm là tín hiệu nhanh, nhưng Defender, SearchIndexer và các process backup có thể chạm file hợp lệ. Nên allowlist theo full path, signer, hash hoặc process role; không allowlist chỉ theo tên file một cách rộng.

Response an toàn hơn là preserve evidence, ghi PID/filename, kiểm tra nhiều file bị đổi và xem process tree trước khi suspend hoặc terminate.

WK01 có Sysmon Event 11 do `Explorer.EXE` tạo shortcut `.lnk` trong thư mục `Recent`; tên shortcut chứa `_financial_payroll_2026`. Rule dùng substring filename sẽ coi shortcut này như canary thật. Active Response đã được cấu hình cho `100200` dù rule chưa được nạp; handler tìm PID trong 10 Event 11 gần nhất rồi thử suspend và terminate. Cần phân biệt đúng path/extension và xác nhận process trước khi bật response.

## Nguyên tắc chung

- Không tối ưu một rule chỉ để đạt precision đẹp trên 17 fixture.
- Ghi lại lý do mỗi tuning change.
- Sau mỗi thay đổi, chạy lại baseline và safety.
- Bất kỳ action có thể làm gián đoạn người dùng phải có manual approval hoặc playbook rõ ràng.

## Candidate cho shortcut

`NEG-100200-002` dựng lại record 8390 đã xuất từ WK01, thay username/domain bằng dữ liệu mẫu. Safety chỉ loại `!_financial_payroll_2026.txt.lnk` ngay trong `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent` khỏi detection canary. Explorer ghi canary `.txt` vẫn phải match. Đây là sửa phạm vi file được bảo vệ, không phải xác nhận process hoặc shortcut là an toàn. [Case study](canary-shortcut-case-study.md) ghi nguồn, hash và các kiểm thử giới hạn.
