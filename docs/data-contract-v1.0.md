# Scanner Data Contract v1.0 (Draft for Team Sign-off)

Bản hợp đồng JSON thống nhất giữa **Khánh (Core Engine)**, **Duy (Collector & Benchmark Runner)** và **Vân (Detector `P`, OWASP, Trust Score, Report & Review Queue)**.

- **JSON Schema chính thức:** [schema-v1.0.json](schema-v1.0.json)
- **Python dataclasses chuẩn:** [models.py](../src/mcp_scanner/models.py)
- **3 file JSON mẫu để Duy & Vân làm việc song song ngay:**
  1. [sample_malicious.json](../examples/schema-v1.0/sample_malicious.json) — Ca có nhiều finding (`M`, `C`, `S`, `P`), bằng chứng đã che secret, OWASP `:2025`, Trust Score thấp (`15`), TL;DR Top 5, `requires_review = true`, `exit_code = 1`.
  2. [sample_clean.json](../examples/schema-v1.0/sample_clean.json) — Ca lành (`0` finding rủi ro, có `1` `capability_info` hợp lệ không bị trừ điểm), Trust Score `100`, `scan_status = complete`, `exit_code = 0`.
  3. [sample_partial.json](../examples/schema-v1.0/sample_partial.json) — Ca quét thiếu (giả lập 1 file bị Windows Defender khóa đọc → `coverage.read_errors`), `scan_status = partial`, `observed_score = 100` nhưng `displayed_score = 60` (`score_scope = provisional`), `exit_code = 2`.

---

## 1. Phân quyền Khối Dữ liệu (Ai tạo — Ai đọc)

| Khối JSON trong `ScanReport` | Người điền chính | Người tiêu thụ chính | Ghi chú quan trọng |
|---|---|---|---|
| `scanner`, `input_provenance`, `coverage`, `telemetry`, `discovered_servers`, `diagnostics` | **Khánh** (Engine) + **Duy** (Provenance từ Collector) | Duy (Benchmark/Monitoring) & Vân (Report) | Mọi lỗi đọc file / Defender / timeout bắt buộc ghi vào `coverage.read_errors` hoặc `diagnostics`, không bao giờ đổi sang `complete`. |
| `findings[]` (code `M`, `C`, `S`, `dynamic_code_execution`, `supply_chain`, `config_auth`) | **Khánh** | Vân (Scoring/OWASP/Report) & Duy (Benchmark) | Luôn giữ cả `declaration_span`, `sink_span`, `trace[]`, `redacted_evidence` (đã che secret bằng `redact_secrets()`). |
| `findings[]` (bề mặt `P`, JS/TS metadata, snapshot diff) | **Vân** | Vân (Report/Review) & Duy (Benchmark) | Dùng chung class `Finding` trong `models.py`. |
| `findings[].owasp_mapping`, `trust_score`, `executive_summary`, `review_queue` | **Vân** | Duy (Log/Thống kê) & Human Reviewer | `trust_score` chỉ phục vụ ưu tiên review; tách biệt hoàn toàn khỏi nhãn chấm benchmark của Duy. |

---

## 2. Quy tắc Cứng Bắt buộc

1. **Ưu tiên CLI Exit Code (`compute_exit_code`):**
   - `2` (`scan_fail`): Khi `scan_status` là `failed`, `partial`, hoặc `unsupported` (lỗi quét hoặc thiếu bề mặt bắt buộc **luôn ưu tiên hơn `clean`** để CI không cho qua nhầm).
   - `1` (`policy_fail`): Khi `scan_status == "complete"` nhưng `policy_status == "fail"`.
   - `0` (`clean`): Chỉ khi `scan_status == "complete"` và `policy_status` là `pass` hoặc `not_evaluated`.
2. **Tách `category` cho Locked Rule-to-Label Policy (Duy):**
   - Nhãn chấm M/C/S/P chỉ xét `category ∈ {"M", "C", "S", "P"}` và `kind ∈ {"malicious_behavior", "vulnerability", "semantic_indicator"}`.
   - Các loại `dynamic_code_execution`, `supply_chain`, `config_auth`, `capability_info` được giữ riêng rạch ròi, không trộn làm nhiễu điểm strict M/C/S/P.
3. **Chống đếm trùng điểm (Vân):**
   - Mỗi finding có `root_cause_group_id`. Hai detector nhìn cùng 1 trace gốc (ví dụ `python_ast` + `semgrep_ce`) được gom vào cùng `root_cause_group_id`, gộp `evidence_sources`, và chỉ đóng góp **tối đa 1 lần** vào `trust_score.contributing_finding_ids`.
4. **Tương thích ngược `v0.1`:**
   - Các lệnh `inventory`, `discover`, `scan-code` hiện có giữ nguyên hợp đồng `v0.1`.
   - Hàm `findings_from_v01_semgrep_artifact()` trong `models.py` chuyển đổi trực tiếp kết quả `semgrep_adapter.scan_code()` sang `Finding` `v1.0`.
