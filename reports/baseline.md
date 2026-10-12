# Baseline — trước khi containment

1. **Chưa.** `agent.loop._naive_loop()` không tạo principal/run identity hoặc scope cho tool call.
2. **Không có policy gate.** `_naive_loop()` gọi `tools.http_post()` trực tiếp khi mock tìm thấy chỉ thị; `agent.tools.http_post()` chỉ giới hạn đích localhost để giữ bài lab an toàn, không cấp quyền.
3. `reports/attack-before.log` ghi POST tới `/reconcile`, gồm duy nhất record synthetic `KH-000999`. Đây là baseline trước containment; không phải dữ liệu khách hàng thật.
