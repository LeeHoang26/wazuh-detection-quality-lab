# Từ điển thuật ngữ SOC cho người mới

Các định nghĩa dưới đây cố tình viết ngắn và dễ hiểu. Khi phỏng vấn, anh không cần đọc thuộc từng câu; chỉ cần hiểu quan hệ giữa log, rule, alert và quyết định của analyst.

| Thuật ngữ | Giải thích dễ hiểu |
| --- | --- |
| SOC | Security Operations Center, đội hoặc bộ phận theo dõi và xử lý sự kiện an ninh. |
| SIEM | Hệ thống gom log từ nhiều máy, tìm mẫu đáng ngờ và tạo alert. Wazuh có thể làm vai trò SIEM/XDR trong lab này. |
| Wazuh | Nền tảng mã nguồn mở dùng để thu thập log, phân tích rule, quản lý agent và tạo alert. |
| Sysmon | Công cụ của Microsoft ghi lại hoạt động chi tiết trên Windows như process tạo ra và file bị sửa. |
| Log | Dòng thông tin do hệ điều hành hoặc ứng dụng ghi lại. Ví dụ: ai đăng nhập, process nào chạy. |
| Event | Một sự kiện cụ thể trong log. Windows đánh số event bằng Event ID, ví dụ 4769 hoặc 4662. |
| Telemetry | Dữ liệu quan sát được từ máy: log, process, network connection, file change. |
| Alert | Thông báo do rule tạo ra khi dữ liệu trông giống hành vi đáng ngờ. Alert chưa đồng nghĩa với kết luận bị tấn công. |
| Detection rule | Điều kiện để hệ thống quyết định có tạo alert hay không. |
| Detection hypothesis | Giả thuyết cần kiểm chứng, ví dụ “RC4 service ticket có thể là Kerberoasting”. |
| Fixture | Một mẫu dữ liệu test cố định, đã làm sạch, dùng để chạy lại cùng một bài kiểm tra nhiều lần. |
| Positive case | Mẫu được thiết kế để đại diện cho hành vi xấu; rule nên tạo alert. |
| Negative case | Mẫu hành vi bình thường; rule không nên tạo alert. |
| Edge case | Mẫu ở ranh giới: có dấu hiệu giống tấn công nhưng thiếu thông tin hoặc có khả năng hợp lệ. |
| True Positive (TP) | Có hành vi đáng ngờ và rule bắt đúng. |
| False Positive (FP) | Hành vi bình thường nhưng rule báo động nhầm. |
| False Negative (FN) | Hành vi đáng ngờ nhưng rule bỏ sót. |
| True Negative (TN) | Hành vi bình thường và rule không báo động. |
| Precision | TP chia cho toàn bộ alert. Precision cao nghĩa là ít báo nhầm. |
| Recall | TP chia cho toàn bộ hành vi xấu. Recall cao nghĩa là ít bỏ sót. |
| Regression test | Chạy lại bộ test sau khi sửa rule để biết hành vi cũ có bị hỏng không. |
| Baseline | Phiên bản tham chiếu ban đầu của rule hoặc kết quả trước khi tuning. |
| Safety profile | Cách chấm thận trọng hơn, yêu cầu thêm context hoặc chuyển case chưa chắc chắn cho người xem. |
| Context | Thông tin giúp analyst hiểu alert: username, source IP, process ID, command line, parent process. |
| Telemetry gap | Chỗ dữ liệu bị thiếu, ví dụ Sysmon có process nhưng không có source IP. |
| Correlation | Ghép nhiều event liên quan để có kết luận tốt hơn. Ví dụ ghép Sysmon Event 1 với Security Event 4624. |
| IOC | Indicator of Compromise, dấu hiệu có thể liên quan xâm nhập như IP, hash, domain hoặc filename. |
| MITRE ATT&CK | Bộ kiến thức mô tả kỹ thuật tấn công. Mã `T1558.003` là Kerberoasting. |
| Kerberoasting | Kỹ thuật xin service ticket Kerberos, thường quan tâm ticket dùng RC4 để cố lấy hash dịch vụ và crack offline. |
| AS-REP Roasting | Kỹ thuật lợi dụng tài khoản không yêu cầu Kerberos pre-authentication để lấy dữ liệu ticket có thể crack. |
| DCSync | Kỹ thuật giả lập quyền domain replication để yêu cầu dữ liệu credential từ Domain Controller. |
| Lateral movement | Việc kẻ tấn công di chuyển từ máy này sang máy khác trong mạng. |
| WMI | Windows Management Instrumentation, cơ chế quản trị Windows có thể được dùng để chạy lệnh từ xa. |
| WinRM | Windows Remote Management, cơ chế quản trị từ xa; `wsmprovhost.exe` thường xuất hiện trong phiên PowerShell remoting. |
| Parent process | Process cha đã tạo ra process con. Quan hệ `WmiPrvSE.exe -> cmd.exe` là context đáng chú ý. |
| Command line | Câu lệnh đầy đủ dùng để chạy process. Nó giúp analyst biết process thực sự làm gì. |
| Canary file | File mồi có tên riêng; việc bị sửa có thể là tín hiệu ransomware. Nó không tự chứng minh có ransomware. |
| Ransomware | Malware mã hóa hoặc phá dữ liệu để đòi tiền. Trong lab chỉ dùng process mô phỏng và file mồi. |
| Manual review | Chuyển alert cho người kiểm tra thay vì tự động cách ly hoặc kill process. |
| Containment | Biện pháp giới hạn phạm vi sự cố, ví dụ cô lập máy hoặc vô hiệu hóa tài khoản theo playbook được duyệt. |
| SOAR | Security Orchestration, Automation and Response, hệ thống tự động nối alert với các bước xử lý. |
| Active response | Hành động tự động sau alert, ví dụ block IP hoặc disable account. Rủi ro cao hơn việc chỉ tạo alert. |
| Wazuh Manager | Thành phần trung tâm nhận dữ liệu, phân tích rule và quản lý agent. |
| Wazuh Agent | Chương trình cài trên máy cần giám sát, gửi telemetry về Manager. |
| `wazuh-logtest` | Công cụ dòng lệnh để đưa một log vào Wazuh và xem decoder/rule nào match. |
| Rule ID | Mã định danh của rule. Repo này dùng `100100`, `100101`, `100102`, `100200`, `100300`. |
| Rule level | Mức độ nghiêm trọng mà Wazuh gán cho alert. Level cao không tự động có nghĩa là chắc chắn bị tấn công. |
| Decoder | Bộ phận đọc cấu trúc log và tách field để rule sử dụng. |
| Event 4768 | Windows Kerberos TGT request. Repo dùng nó cho AS-REP Roasting. |
| Event 4769 | Windows Kerberos service ticket request. Repo dùng nó cho Kerberoasting. |
| Event 4662 | Windows object operation. Một số quyền replication trong event có thể liên quan DCSync. |
| Sysmon Event 1 | Process creation: process nào chạy, process cha, command line. |
| Sysmon Event 11 | FileCreate: process nào tạo hoặc chạm vào file nào. |
| Source IP | Địa chỉ IP của máy khởi nguồn kết nối hoặc hoạt động. Thiếu nó thì khó biết hoạt động đến từ đâu. |
| Tuning | Điều chỉnh rule để giảm FP, giảm FN và yêu cầu context phù hợp hơn. |
| Evidence preservation | Giữ lại log, PID, command line, memory hoặc file để điều tra; không vội xóa bằng chứng. |

## Quan hệ giữa các thuật ngữ

Có thể nhớ theo chuỗi này:

```text
Máy tạo telemetry -> Wazuh decoder -> detection rule -> alert -> analyst xem context -> quyết định
```

Trong repo này:

```text
fixture -> matcher offline -> TP/FP/FN/TN -> report -> so sánh với wazuh-logtest
```

Tên action như `suspend_dump_terminate` trong fixture chỉ là mô tả quyết định dự kiến để thảo luận. Script không thực hiện các hành động đó.
