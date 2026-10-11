# 🛡️ BankSim Security Policy & Threat Boundary Specification

## 1. Security Architecture & Threat Boundaries

BankSim enforces an adversarial **Blue-Team Defense-in-Depth** model designed for financial AI architectures.

### Architectural Boundary Invariants
1. **Control vs. Data Plane Isolation**:
   - Untrusted user input (transaction memos, invoice notes, unstructured prompts) is treated strictly as passive payload data.
   - Untrusted strings are **never** interpolated directly into database queries, ledger execution logic, or system instruction controls.
2. **Fail-Closed Fallback Guarantee**:
   - If upstream LLM APIs (e.g. Google Gemini) experience network dropouts, quota exhaustion, timeouts, or format errors, the firewall pipeline automatically defaults to a deterministic, fail-closed inspection engine.
   - At no point does the system "fail open" or permit uninspected transactions to settle on the banking ledger.
3. **Deterministic Pre-Flight Interception (Layer 0)**:
   - High-confidence structural threats (sanctioned entities, overdrafts, account draining, disproportionate retail costs, overt prompt override patterns) are halted in $< 1\text{ ms}$ before any downstream model invocation.
4. **Structured Output Invariance**:
   - Model responses must strictly adhere to the typed Pydantic `FirewallDecision` schema. Malformed, non-JSON, or schema-violating outputs are immediately quarantined by defensive exception handlers.

---

## 2. Cryptographic Integrity & Secret Management

- **Zero-Storage for Sensitive Keys**: BankSim does not log, persist, or expose API keys. Secrets are read transiently from environment variables (`GEMINI_API_KEY`) or Streamlit secrets (`st.secrets`).
- **Audit Trail Immutability**: All transaction evaluations generate structured audit logs capturing timestamps, decision layers, threat classifications, risk scores, and forensic rationale for SIEM aggregation.

---

## 3. Vulnerability Reporting & Disclosure Policy

The BankSim Blue-Team welcomes responsible disclosure of vulnerabilities, novel prompt injection bypasses, or ledger subversions.

### Incident Reporting SLA
- **Initial Response SLA**: Within **24 hours** of receipt.
- **Triage & Reproducibility Assessment**: Within **48 hours**.
- **Defensive Patch Deployment**: Within **5 business days** for high-severity prompt jailbreaks or business-logic bypasses.

### How to Report
If you discover a security issue or novel adversarial bypass vector:
1. **Do not create a public GitHub issue**.
2. Email your proof-of-concept (PoC) payload, expected vs. actual behavior, and severity assessment to:
   - **Security Contact**: `security@banksim-firewall.local` / `leenaparthiban@users.noreply.github.com`
3. Include:
   - The exact transaction payload (Action, Sender, Recipient, Amount, Memo).
   - The firewall model and threshold settings.
   - Steps to reproduce or adversarial evasion rationale.
