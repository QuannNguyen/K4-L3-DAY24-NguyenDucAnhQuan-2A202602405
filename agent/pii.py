"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re

_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+(?![\w-])", re.IGNORECASE)
_CCCD = re.compile(r"(?<!\d)\d{12}(?!\d)")
_BANK_LABEL = re.compile(
    r"(?i)(?:\bSTK\b|số\s*tài\s*khoản|tài\s*khoản)\s*[:#-]?\s*"
    r"((?:\d[\s-]?){7,15}\d)(?!\d)"
)
_PHONE_LABEL = re.compile(
    r"(?i)(?:\bSĐT\b|số\s*điện\s*thoại|điện\s*thoại)\s*[:#-]?\s*"
    r"(0(?:[\s.-]?\d){9,10})(?!\d)"
)
_PHONE = re.compile(r"(?<!\d)0(?:[\s.-]?\d){9,10}(?!\d)")


def detect(text: str) -> list[dict]:
    candidates: list[dict] = []
    claimed: list[tuple[int, int]] = []

    def add(kind: str, start: int, end: int) -> None:
        if any(start < occupied_end and occupied_start < end
               for occupied_start, occupied_end in claimed):
            return
        candidates.append({"type": kind, "start": start, "end": end})
        claimed.append((start, end))

    for match in _BANK_LABEL.finditer(text):
        add("VN_BANK_ACCOUNT", *match.span(1))
    for match in _CCCD.finditer(text):
        add("VN_CCCD", *match.span())
    for match in _PHONE_LABEL.finditer(text):
        add("VN_PHONE", *match.span(1))
    for match in _PHONE.finditer(text):
        add("VN_PHONE", *match.span())
    for match in _EMAIL.finditer(text):
        add("EMAIL", *match.span())

    return sorted(candidates, key=lambda entity: (entity["start"], entity["end"]))


def redact(text: str) -> str:
    redacted = text
    for entity in reversed(detect(text)):
        replacement = f"[REDACTED_{entity['type']}]"
        redacted = redacted[:entity["start"]] + replacement + redacted[entity["end"]:]
    return redacted
