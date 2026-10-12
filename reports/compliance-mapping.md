# Compliance mapping — kỹ thuật lab

| Nguồn / yêu cầu | Control đã làm | Evidence file:dòng | Giới hạn |
|---|---|---|---|
| Luật 91/2025/QH15 | Phát hiện/redact CCCD, điện thoại, STK, email; không chuyển raw ticket text sang Run B. | `agent/pii.py:48-78`; `agent/runner.py:88-115,182-186` | Chỉ đối chiếu ở mức chủ đề dữ liệu cá nhân; chưa xác minh điều khoản, chưa phải kết luận tuân thủ. |
| NĐ 356/2025/NĐ-CP | Kiểm tra purpose, principal, scope, delegation và TTL trước tool; mọi quyết định có reason trong hash chain. | `agent/policy.py:63-101`; `agent/runner.py:118-151`; `agent/ledger.py:57-99` | Chưa đối chiếu điều khoản văn bản gốc; principal là fixture mô phỏng, ledger cục bộ không phải kho audit production. |
| Luật AI 134/2025/QH15 | Hạn chế quyền theo principal và ngăn restricted egress sau prompt injection. | `agent/policy.py:63-101`; `agent/runner.py:154-186`; `reports/ledger.jsonl` (deny record) | Tên nguồn lấy từ rubric; không diễn giải nghĩa vụ pháp lý hoặc khẳng định hệ thống đáp ứng luật. |
| OWASP ASI01, ASI03, ASI04 | ASI01: chỉ ID số từ tên file đi qua split; ASI03: OBO scope và TTL; ASI04: pinned Gitleaks, hashed lock và incident handling. | `agent/runner.py:88-115`; `agent/policy.py:78-101`; `.pre-commit-config.yaml:1-7`; `requirements.lock`; `reports/secrets-incident.md` | Mapping tham khảo theo chủ đề; test mock không đánh giá triển khai production hay toàn bộ threat model. |

Các tên luật/nghị định phía trên được giữ nguyên theo rubric lớp. Chưa ghi số điều khoản vì chưa đối chiếu văn bản chính thức. Mô phỏng kỹ thuật và evidence của repo không tự chứng minh tuân thủ pháp luật.
