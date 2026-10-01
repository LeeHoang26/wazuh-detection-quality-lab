# Tuning notes

## Kerberoasting

Một request service ticket dùng RC4 là tín hiệu đáng chú ý nhưng chưa đủ mạnh để kết luận. Có ứng dụng cũ vẫn dùng RC4. Nên bổ sung tần suất request, danh sách service account, username, source IP và lịch sử hành vi trước khi tự động response.

Nếu thiếu `targetUserName` hoặc `ipAddress`, alert vẫn có thể có giá trị để điều tra nhưng nên chuyển `manual_review` thay vì hành động mạnh.

## AS-REP Roasting

`preAuthType=0` cộng với encryption type đáng chú ý giúp nhận diện mẫu AS-REP. Tuy nhiên việc disable account hoặc đổi password phải đi qua IAM playbook đã được phê duyệt. Alert detection không tự nó là quyền cho phép khóa tài khoản.

## DCSync

Replication GUID là context quan trọng hơn một event 4662 chung chung. Production cần biết identity đó có phải Domain Controller hoặc service account được phép replication không. Vì vậy cần allowlist có kiểm soát và điều tra subject account.

## WMI và WinRM lateral movement

Quan hệ parent-child như `WmiPrvSE.exe -> cmd.exe` hoặc `wsmprovhost.exe -> powershell.exe` giúp phát hiện remote shell. Sysmon Event 1 thường không cho biết đầy đủ source IP. Cần correlate với Security Event 4624 và các event mạng để biết máy nguồn.

Nếu command line bị thiếu, vẫn giữ alert để analyst xem nhưng không nên tự động isolate chỉ từ một process lineage chưa đủ context.

## Canary ransomware

Canary filename bị chạm là tín hiệu nhanh, nhưng Defender, SearchIndexer và các process backup có thể chạm file hợp lệ. Nên allowlist theo full path, signer, hash hoặc process role; không allowlist chỉ theo tên file một cách rộng.

Response an toàn hơn là preserve evidence, ghi PID/filename, kiểm tra nhiều file bị đổi và xem process tree trước khi suspend hoặc terminate.

## Nguyên tắc chung

- Không tối ưu một rule chỉ để đạt precision đẹp trên 15 fixture.
- Ghi lại lý do mỗi tuning change.
- Sau mỗi thay đổi, chạy lại baseline và safety.
- Bất kỳ action có thể làm gián đoạn người dùng phải có manual approval hoặc playbook rõ ràng.
