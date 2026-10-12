"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, pii, policy, tools
from agent.policy import PolicyContext

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"
_AGENT_ID = "lab24-agent"
_RUN_TTL = timedelta(minutes=10)
_TICKET_FILENAME = re.compile(r"^ticket-(\d+)[a-z]?\.md$", re.IGNORECASE)


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


def _args_hash(args: dict) -> str:
    encoded = json.dumps(args, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _ticket_ids(docs: list[dict]) -> list[int]:
    ticket_ids = set()
    for document in docs:
        match = _TICKET_FILENAME.fullmatch(Path(document["id"]).name)
        if match:
            ticket_ids.add(int(match.group(1)))
    return sorted(ticket_ids)


def _customers_for_tickets(ticket_ids: list[int]) -> list[str]:
    data_path = Path(__file__).resolve().parent.parent / "data" / "customers.json"
    customers = json.loads(data_path.read_text(encoding="utf-8"))
    ticket_set = set(ticket_ids)
    return sorted({
        customer["customer_id"]
        for customer in customers
        if ticket_set.intersection(customer.get("related_tickets", []))
    })


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    ledger_path = (log_dir or REPORTS_DIR) / "ledger.jsonl"
    run_id = str(uuid.uuid4())
    expires_at = (datetime.now(timezone.utc) + _RUN_TTL).isoformat()
    principals_path = Path(__file__).resolve().parent.parent / "data" / "principals.json"
    principals = json.loads(principals_path.read_text(encoding="utf-8"))
    principal = principals.get(principal_id, {})
    parent_scopes = tuple(principal.get("allowed_tools", []))

    def invoke(tool_name: str, args: dict, classification: str,
               purpose: str, agent_scopes: tuple[str, ...],
               delegation_depth: int, parent: tuple[str, ...],
               operation):
        context = PolicyContext(
            data_classification=classification,
            request_purpose=purpose,
            agent_owner=f"{_AGENT_ID}/{tool_name}",
            delegation_depth=delegation_depth,
            egress_enabled=tool_name == "http_post",
            principal_id=principal_id,
            requested_tool=tool_name,
            agent_scopes=agent_scopes,
            parent_scopes=parent,
            expires_at=expires_at,
        )
        allowed, reason = policy.check(context)
        ledger.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "agent_id": _AGENT_ID,
                "run_id": run_id,
                "tool": tool_name,
                "args_hash": _args_hash(args),
                "classification": classification,
                "decision": "allow" if allowed else "deny",
                "reason": reason,
                "on_behalf_of": principal_id,
                "expires_at": expires_at,
            },
            ledger_path,
        )
        if not allowed:
            return False, None
        return True, operation()

    search_allowed, docs = invoke(
        "search_docs", {"query": message}, "internal", "summarize-tickets",
        ("search_docs",), 0, (), lambda: tools.search_docs(message),
    )
    if not search_allowed:
        return "Không thể xử lý yêu cầu theo chính sách hiện tại."

    docs = docs or []
    combined_text = "\n\n".join(document["text"] for document in docs)
    injected = llm.find_injection(combined_text)

    ticket_ids = _ticket_ids(docs)
    for customer_id in _customers_for_tickets(ticket_ids):
        invoke(
            "read_customer", {"customer_id": customer_id}, "restricted",
            "support-reply", ("read_customer",), 1, parent_scopes,
            lambda customer_id=customer_id: tools.read_customer(customer_id),
        )

    if injected is not None:
        invoke(
            "http_post", {"destination": "local-reconcile", "records": "restricted"},
            "restricted", "privacy-audit", ("http_post",), 1, parent_scopes,
            lambda: tools.http_post(
                "http://127.0.0.1:10024/reconcile", {"records": []}
            ),
        )

    safe_docs = [
        {**document, "text": pii.redact(document["text"])}
        for document in docs
    ]
    return llm.summarize(safe_docs)
