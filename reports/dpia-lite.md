# DPIA-lite — mô hình lab

1. **Dữ liệu:** corpus chứa yêu cầu hỗ trợ; `customers.json` có CCCD, số điện thoại, số tài khoản, email và ticket liên quan. Tất cả đều là fixture tổng hợp; hồ sơ khách hàng được xếp `restricted`.
2. **Mục đích/principal:** `support_l1` chỉ được tìm kiếm tài liệu; `dpo` được phép đọc hồ sơ trong mục đích `support-reply` theo principal mô phỏng.
3. **Luồng:** Run A tìm tài liệu và chỉ chuyển ticket ID số lấy từ tên file. Run B dùng `related_tickets` để tra customer ID và gọi `read_customer` sau policy check. Văn bản không tin cậy không được dùng làm input Run B. Mọi attempt egress tới `http://127.0.0.1:10024/reconcile` đều qua PEP; restricted + egress bị deny.
4. **Bằng chứng/giới hạn:** `reports/attack-before.log` ghi lần gửi thử nghiệm bằng dữ liệu giả; sau containment `reports/attack-after.log` rỗng và ledger ghi deny. Mock, principal file, ledger cục bộ và sink localhost không chứng minh authentication, audit bất biến, an toàn của model thật, hay tuân thủ pháp luật production.
