# Secret giả trong lịch sử Git

- **Scanner:** Gitleaks 8.30.1; release checksum verified.
- **Commit:** `1bdd849922156c868a5ee9293d68f5b72e242d2c`.
- **Lịch sử:** một finding `lab24-synthetic-token` in `lab-fake-secret.txt:1`; đúng token giả, vô hiệu, được seed cho bài lab. Không ghi giá trị token vào báo cáo.
- **Working tree:** `gitleaks dir --config .gitleaks.toml --redact --verbose .` báo không tìm thấy secret.
- **Nếu là credential thật:** thu hồi và rotate ngay tại hệ thống phát hành, kiểm tra audit log và downstream usage, sau đó mới loại credential khỏi lịch sử theo quy trình phù hợp.
- **Giới hạn:** xoá file khỏi HEAD không vô hiệu credential từng bị lộ trong commit cũ. Pin dependency và pre-commit giảm rủi ro supply chain/commit tiếp theo nhưng cũng không thu hồi credential.
