Simplified Oracle List View (Current Stable Version)

Overview
- Purpose: Load and display rows from the Oracle table configured in `ORACLE_TABLE_CLIENTES` without authentication or heavy pagination.
- Status: This is the current, working, and intentionally simple version. Keep as‑is unless a change is explicitly requested.

Key Behavior
- Endpoint: `GET /api/clientes`
  - Returns the first N rows from the Oracle table using `ROWNUM <= :1`.
  - Query (parameters bound positionally):
    - `SELECT CONTRATO, MATRICULA, COMPETENCIA_PAGAMENTO, BENEFICIARIO, VALOR
       FROM (
         SELECT CONTRATO, MATRICULA, COMPETENCIA_PAGAMENTO, BENEFICIARIO, VALOR
         FROM {ORACLE_TABLE_CLIENTES}
       )
       WHERE ROWNUM <= :1`
  - Request parameter: `limit` (defaults to 10, capped by `MAX_PAGE_SIZE`).
  - Response shape (kept compatible with the frontend):
    - `{ "clientes": [...], "page": 1, "limit": <limit>, "total": 0 }`
    - `total = 0` is intentional to hide pagination in the UI.
  - No authentication required for this endpoint.

- Health check: `GET /healthz` → `{ "ok": true }` when both SQLite and Oracle are reachable for basic checks.

Frontend (templates/index.html)
- Uses etchJSON(API.clientes(page, limit), {}, 60000) with a 60s timeout just for this call.
- Renders the 5 columns used by the API: CONTRATO, MATRICULA, COMPETENCIA_PAGAMENTO, BENEFICIARIO, VALOR.
- Shows a friendly error message when the request times out.

Form Load (Matricula ? Prefill)
- Trigger: modal "Novo Cadastro" ap�s informar a matr�cula.
- Endpoint: GET /api/ultimo-cadastro-por-matricula?matricula=<MATRICULA> (no auth).
- Backend logic:
  - Latest row for the matr�cula with TIPO_ATENDIMENTO = 'REMOCAO' via ROW_NUMBER() ordered by COMPETENCIA_PROCESSAMENTO DESC, SEQUENCIA DESC.
  - LEFT JOIN with SELECT MAX(SEQUENCIA) to provide SEQUENCIA_GERAL and PROXIMA_SEQUENCIA.
- Frontend handling:
  - Ensures TIPO_ATENDIMENTO = 'REMOCAO' if missing.
  - Prefills SEQUENCIA from PROXIMA_SEQUENCIA (read-only field).
  - Keeps user-typed MATRICULA.
  - Clears required fields so the user must fill them (except MATRICULA and SEQUENCIA):
    MATRICULA, COMPETENCIA_PAGAMENTO, ITEM_COD, VALOR, COMPETENCIA_PROCESSAMENTO, DATA_EXECUCAO, IDADE, UNI_COD_RESPON, COD_CNTRAT_CART, COD, COD_DEPNTE, BENEFICIARIO, ITEM_DESCRI.
- Uses `fetchJSON(API.clientes(page, limit), {}, 60000)` with a 60s timeout just for this call.
- Renders the 5 columns used by the API: `CONTRATO`, `MATRICULA`, `COMPETENCIA_PAGAMENTO`, `BENEFICIARIO`, `VALOR`.
- Shows user‑friendly error message when the request times out.

Configuration (.env)
- `ORACLE_TABLE_CLIENTES=uni0177_tbtipoguia_comp` (change to `OWNER.uni0177_tbtipoguia_comp` if the table is under a specific schema).
- `MAX_PAGE_SIZE=100`
- Oracle connection parameters must be set according to your environment (host, service, user, password, THICK client path, etc.).

Performance Notes
- This simple approach avoids `COUNT(*)` and `ROW_NUMBER` windowing to keep latency predictable on large tables.
- If you need deterministic ordering, add an `ORDER BY` plus a suitable index — but be aware of potential cost on big tables.

How to Evolve (only if needed later)
- Classic pagination (ROW_NUMBER) for Oracle 11g:
  - Replace the simple select with a windowed query and `RN BETWEEN :start AND :end`.
- OFFSET/FETCH (Oracle 12c+):
  - `... ORDER BY <indexed_column> OFFSET :off ROWS FETCH NEXT :lim ROWS ONLY`.
- Any change should preserve the response shape and be tested for performance before switching.

Troubleshooting
- If `AbortError` appears in the browser console, check the API latency and server logs.
- For Oracle timeouts (`DPY-4024` / `ORA-03156`), validate network stability, service availability, and indexes.

Stability Policy
- This document describes the agreed “do not change” baseline. Avoid modifying `app.py` and `templates/index.html` behaviors described above unless there is a new explicit request.




Saving New Records
- Endpoint: POST /api/cadastrar-cliente
- Backend filters payload keys to valid table columns and inserts with binds.
- Success: HTTP 201 with { "msg": "Cliente cadastrado com sucesso!" }.
