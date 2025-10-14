# app.py
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_restful import Api, Resource
from contextlib import contextmanager
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from collections import OrderedDict
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
import logging
import os
import sys
import platform
import sqlite3
import oracledb

# ====================================================================
# ENV / LOGGING
# ====================================================================
load_dotenv()
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO))
log = logging.getLogger("app")

# ====================================================================
# CONFIG
# ====================================================================
class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev_change_me")

    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    SQLITE_DB_PATH = os.getenv("SQLITE_DB_PATH", os.path.join(BASE_DIR, "relacionamento_cliente.db"))
    SQLITE_TIMEOUT = int(os.getenv("SQLITE_TIMEOUT", "10"))

    ORACLE_USER = os.getenv("ORACLE_USER", "integracaop")
    ORACLE_PASSWORD = os.getenv("ORACLE_PASSWORD", "")
    ORACLE_HOST = os.getenv("ORACLE_HOST", "172.82.0.5")
    ORACLE_PORT = int(os.getenv("ORACLE_PORT", "1521"))
    ORACLE_SERVICE = os.getenv("ORACLE_SERVICE", "integrap.subnetprd.vcnprd.oraclevcn.com")
    ORACLE_THICK_LIB_DIR = os.getenv("ORACLE_THICK_LIB_DIR", "")

    ORACLE_TABLE_CLIENTES = os.getenv("ORACLE_TABLE_CLIENTES", "uni0177_tbtipoguia_comp")

    MAX_PAGE_SIZE = int(os.getenv("MAX_PAGE_SIZE", "100"))

    # Pool / desempenho / timeouts
    ORACLE_POOL_MIN = int(os.getenv("ORACLE_POOL_MIN", "1"))
    ORACLE_POOL_MAX = int(os.getenv("ORACLE_POOL_MAX", "5"))
    ORACLE_POOL_INC = int(os.getenv("ORACLE_POOL_INC", "1"))
    ORACLE_CALL_TIMEOUT_MS = int(os.getenv("ORACLE_CALL_TIMEOUT_MS", "20000"))  # 20s padrão
    ORACLE_STMT_CACHE = int(os.getenv("ORACLE_STMT_CACHE", "100"))

    # Hint opcional para o índice de ordenação (ex.: "INDEX_DESC(u UNI0177_IDX_DTSEQ)")
    ORACLE_INDEX_HINT = os.getenv("ORACLE_INDEX_HINT", "").strip()

    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"

REQUIRE_ORACLE_THICK = True

app = Flask(__name__)
app.config.from_object(Config)
api = Api(app)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=app.config["SESSION_COOKIE_SECURE"],
)

@app.after_request
def _sec_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    return resp

# ====================================================================
# Helpers ENV
# ====================================================================
def _strip_quotes(s: str | None) -> str | None:
    if not s:
        return s
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        return s[1:-1]
    return s

def _norm_path_env(var: str) -> str:
    raw = os.getenv(var, "")
    raw = _strip_quotes(raw) or ""
    return os.path.normpath(os.path.expandvars(raw)) if raw else ""

# ====================================================================
# ORACLE THICK: init obrigatório
# ====================================================================
def _assert_64bit():
    arch, _ = platform.architecture()
    if arch != "64bit":
        raise RuntimeError("Python precisa ser 64-bit para usar Oracle Client 64-bit (THICK).")

def _instant_client_probe(lib_dir: str):
    if not lib_dir or not os.path.isdir(lib_dir):
        raise RuntimeError(
            "ORACLE_THICK_LIB_DIR não configurado ou pasta inválida. "
            "Defina a pasta do Instant Client 64-bit (ex.: C:\\oracle\\instantclient_23_9)."
        )
    if os.name == "nt":
        oci = os.path.join(lib_dir, "oci.dll")
        if not os.path.isfile(oci):
            raise RuntimeError(
                f"Instant Client inválido: não encontrei oci.dll em '{lib_dir}'. "
                "Aponte para a subpasta instantclient_XX_X."
            )
        try:
            os.add_dll_directory(lib_dir)
        except Exception:
            pass
        if lib_dir not in os.environ.get("PATH", ""):
            os.environ["PATH"] = lib_dir + os.pathsep + os.environ.get("PATH", "")
    elif sys.platform.startswith("linux"):
        so = os.path.join(lib_dir, "libclntsh.so")
        if not os.path.isfile(so):
            raise RuntimeError(f"Instant Client inválido: não encontrei libclntsh.so em '{lib_dir}'.")
    elif sys.platform == "darwin":
        dylib = os.path.join(lib_dir, "libclntsh.dylib")
        if not os.path.isfile(dylib):
            raise RuntimeError(f"Instant Client inválido: não encontrei libclntsh.dylib em '{lib_dir}'.")

def _init_oracle_thick_or_fail():
    _assert_64bit()
    lib_dir = _norm_path_env("ORACLE_THICK_LIB_DIR") or app.config["ORACLE_THICK_LIB_DIR"]
    lib_dir = _strip_quotes(lib_dir) or ""
    _instant_client_probe(lib_dir)

    net_admin = _strip_quotes(os.getenv("ORACLE_NET_ADMIN") or "")
    try:
        if net_admin and os.path.isdir(net_admin):
            oracledb.init_oracle_client(lib_dir=lib_dir, config_dir=net_admin)
        else:
            oracledb.init_oracle_client(lib_dir=lib_dir)
        log.info(f"Oracle THICK habilitado (lib_dir={lib_dir}, net_admin={net_admin or 'None'}).")
    except Exception as e:
        raise RuntimeError(
            f"Falha ao iniciar Oracle THICK: {e}. Cheque Instant Client 64-bit, oci.dll e Microsoft VC++ x64."
        ) from e

if REQUIRE_ORACLE_THICK:
    _init_oracle_thick_or_fail()

# ====================================================================
# DSN + POOL + contextmanager
# ====================================================================
ORACLE_DSN = oracledb.makedsn(
    host=app.config["ORACLE_HOST"],
    port=app.config["ORACLE_PORT"],
    service_name=app.config["ORACLE_SERVICE"],
)

POOL = oracledb.create_pool(
    user=app.config["ORACLE_USER"],
    password=app.config["ORACLE_PASSWORD"],
    dsn=ORACLE_DSN,
    min=app.config["ORACLE_POOL_MIN"],
    max=app.config["ORACLE_POOL_MAX"],
    increment=app.config["ORACLE_POOL_INC"],
    homogeneous=True,
    timeout=60,
    stmtcachesize=app.config["ORACLE_STMT_CACHE"],
)

@contextmanager
def get_oracle_conn(call_timeout_ms: int | None = None):
    conn = None
    try:
        conn = POOL.acquire()
        if call_timeout_ms:
            conn.callTimeout = int(call_timeout_ms)  # ms
        yield conn
    except oracledb.Error as e:  # <-- captura genérica compatível
        msg = str(e)
        if "DPY-3001" in msg:
            log.error("Conexão rejeitada: NNE exigido (somente THICK).")
        log.exception("Falha Oracle (get_oracle_conn).")
        raise
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass

# ====================================================================
# ORACLE: COLUNAS & METADADOS
# ====================================================================
_ORACLE_TABLE_COLUMNS = []
_ORACLE_TABLE_METADATA = OrderedDict()

def _split_owner_table(ref: str):
    if not ref:
        return None, None
    parts = ref.split(".")
    if len(parts) == 2:
        return parts[0].upper(), parts[1].upper()
    return None, ref.upper()

def get_oracle_table_columns():
    global _ORACLE_TABLE_COLUMNS
    if _ORACLE_TABLE_COLUMNS:
        return _ORACLE_TABLE_COLUMNS
    try:
        with get_oracle_conn(call_timeout_ms=5000) as conn:
            cur = conn.cursor()
            cur.prefetchrows = 1
            cur.arraysize = 1
            cur.execute(f"SELECT * FROM {app.config['ORACLE_TABLE_CLIENTES']} WHERE ROWNUM = 1")
            _ORACLE_TABLE_COLUMNS = [c[0] for c in (cur.description or [])]
            if not _ORACLE_TABLE_COLUMNS:
                log.warning("Nenhuma coluna encontrada na tabela Oracle (tabela vazia?).")
    except Exception as e:
        log.error(f"Erro ao buscar colunas Oracle: {e}")
        _ORACLE_TABLE_COLUMNS = []
    return _ORACLE_TABLE_COLUMNS

def get_oracle_table_metadata():
    global _ORACLE_TABLE_METADATA
    if _ORACLE_TABLE_METADATA:
        return _ORACLE_TABLE_METADATA

    owner, table = _split_owner_table(app.config['ORACLE_TABLE_CLIENTES'])
    meta = OrderedDict()
    try:
        with get_oracle_conn(call_timeout_ms=8000) as conn:
            cur = conn.cursor()
            if owner:
                cur.execute(
                    """
                    SELECT column_name, data_type, data_precision, data_scale, nullable, column_id
                    FROM all_tab_columns
                    WHERE owner = :p_owner AND table_name = :p_table
                    ORDER BY column_id
                    """,
                    {"p_owner": owner, "p_table": table},
                )
            else:
                cur.execute(
                    """
                    SELECT column_name, data_type, data_precision, data_scale, nullable, column_id
                    FROM user_tab_columns
                    WHERE table_name = :p_table
                    ORDER BY column_id
                    """,
                    {"p_table": table},
                )
            for name, dtype, precision, scale, nullable, col_id in cur:
                meta[name.upper()] = {
                    "data_type": (dtype or "").upper(),
                    "data_precision": precision,
                    "data_scale": scale,
                    "nullable": (nullable or "Y") == "Y",
                    "column_id": col_id,
                }
    except Exception as e:
        log.error(f"Erro ao buscar metadados da tabela Oracle: {e}")
        meta = OrderedDict()

    _ORACLE_TABLE_METADATA = meta
    return _ORACLE_TABLE_METADATA

# ====================================================================
# NORMALIZAÇÃO DE VALORES
# ====================================================================
def normalize_bind_value(column, value, meta):
    if meta is None:
        return value
    if value is None:
        return None

    if isinstance(value, str):
        trimmed = value.strip()
        if trimmed == "":
            return None
        value = trimmed

    dtype = (meta.get("data_type") or "").upper()

    if dtype in {"CHAR", "NCHAR", "VARCHAR2", "NVARCHAR2", "CLOB"}:
        return str(value)

    if dtype in {"DATE", "TIMESTAMP", "TIMESTAMP(6)", "TIMESTAMP WITH TIME ZONE", "TIMESTAMP WITH LOCAL TIME ZONE"}:
        if isinstance(value, datetime):
            return value
        if isinstance(value, date):
            return datetime.combine(value, datetime.min.time())
        if isinstance(value, str):
            candidate = value.replace("Z", "")
            try:
                return datetime.fromisoformat(candidate)
            except ValueError:
                for fmt in ("%d/%m/%Y", "%d-%m-%Y", "%Y%m%d"):
                    try:
                        return datetime.strptime(candidate, fmt)
                    except ValueError:
                        continue
        raise ValueError("formato de data invalido (use AAAA-MM-DD)")

    if dtype == "NUMBER":
        try:
            decimal_value = Decimal(str(value).replace(",", "."))
        except (InvalidOperation, ValueError) as exc:
            raise ValueError("valor numerico invalido") from exc

        scale = meta.get("data_scale")
        if scale and int(scale) > 0:
            return decimal_value
        if decimal_value == decimal_value.to_integral_value():
            return int(decimal_value)
        return decimal_value

    return value

# ====================================================================
# SQLITE (USUÁRIOS)
# ====================================================================
def _resolve_sqlite_path():
    raw = app.config["SQLITE_DB_PATH"]
    return raw if os.path.isabs(raw) else os.path.join(app.config["BASE_DIR"], raw)

def get_sqlite_db():
    db_path = _resolve_sqlite_path()
    dirpath = os.path.dirname(db_path)
    if dirpath:
        os.makedirs(dirpath, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=app.config["SQLITE_TIMEOUT"])
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn

def create_user_table():
    with get_sqlite_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome   TEXT NOT NULL,
                login  TEXT UNIQUE NOT NULL,
                senha  TEXT NOT NULL,
                email  TEXT,
                funcao TEXT NOT NULL
            );
        """)
    log.info(f"SQLite em: {_resolve_sqlite_path()}")

create_user_table()

# ====================================================================
# HELPERS
# ====================================================================
def sanitize(value):
    if isinstance(value, Decimal):
        try:
            return float(value)
        except:
            return None
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value

def row_to_dict(columns, row):
    return {col: sanitize(val) for col, val in zip(columns, row)}

def require_login():
    if 'user_id' not in session:
        return {"msg": "Usuário não autenticado."}, 401

def _today_yyyy_mm_dd():
    return date.today().isoformat()

def _yyyy_mm_now():
    d = date.today()
    return f"{d.year}{d.month:02d}"

# ====================================================================
# REGRAS DE NEGÓCIO (DEFAULTS)
# ====================================================================
BUSINESS_DEFAULTS = {
    "TIPO_ATENDIMENTO": "REMOCAO",
    "STATUS": None,
    "DATPROCESSAMENTO": _today_yyyy_mm_dd,
    "COMPETENCIA_PAGAMENTO": None,
    "TP_GUIA": "P",
    "ITEM_COD": None,
    "TIP_GUIA": "REMOCAO",
    "DEMONSTRATIVO_FATURA": None,
    "COMPETENCIA_PROCESSAMENTO": _yyyy_mm_now,
    "GUCID_COD_CID": None,
    "TP_ITEM": "Taxa",
    "SEQ": 1,
    "DATA_EXECUCAO": _today_yyyy_mm_dd,
    "LOCALIDADE": "LOCAL",
    "GRUPO_FREQUENCIA": None,
    "PREST_PAG": None,
    "TIP_FOR": "REM",
    "ITEM_DESCRI": None,
    "NM_SOLIC": None,
    "NC": "S",
    "TIPO_LANCAMENTO": "PRODUCAO - REMOCAO",
    "CAPITULO": "TAXA",
    "GRUPO": "TAXA",
    "SUBGRUPO": "TAXA",
    "TIPO_ACOMODACAO": None,
    "PARTICIPACAO": "SEM PARTICIPACAO",
    "UNIMED": "LOCAL",
    "CBO_EXEC_NRO": None,
    "CBO_SOLIC_NRO": None,
    "VAL_FAT": 0,
    "FAT_NRO": 0,
    "COD_PREST_PAGTO": None,
    "UNI_COD_RESPON": 177,
    "GUITE_NRO_SENHA_SOLIT": None,
    "PRESTADOR_EXECUTANTE_ITEM": None,
    "PARAMETRO_INT": None,
    "PARAMETRO_LOC": None,
    "CPFCNPJ_EXEC": None,
    "CPFCNPJ_SOL": None,
    "OBSERVACO": None,
    "ORIGEM_REDE": "OUTRA OPERADORA",
    "CARATER_ATENDIMENTO": "E",
}

def apply_business_defaults(record: dict) -> dict:
    out = dict(record or {})
    for key, default in BUSINESS_DEFAULTS.items():
        if key not in out or out[key] in ("", None):
            out[key] = default() if callable(default) else default

    if "SEQUENCIA" not in out and out.get("PROXIMA_SEQUENCIA") is not None:
        try:
            out["SEQUENCIA"] = int(out["PROXIMA_SEQUENCIA"])
        except Exception:
            pass

    out["SEQ"] = 1

    for k in ("DATPROCESSAMENTO", "DATA_EXECUCAO"):
        if out.get(k):
            out[k] = str(out[k]).split("T")[0]
    return out

def get_next_global_sequence(conn) -> int:
    cur = conn.cursor()
    cur.execute(f"SELECT NVL(MAX(SEQUENCIA),0) + 1 FROM {app.config['ORACLE_TABLE_CLIENTES']}")
    row = cur.fetchone()
    try:
        return int(row[0]) if row and row[0] is not None else 1
    except Exception:
        return 1

# ====================================================================
# ROTAS HTML
# ====================================================================
@app.route("/")
def home():
    return redirect(url_for('clientes_view' if 'user_id' in session else 'login_view'))

@app.route("/login")
def login_view():
    return render_template("login.html") if 'user_id' not in session else redirect(url_for('clientes_view'))

@app.route("/cadastro")
def cadastro_view():
    return render_template("cadastro.html") if 'user_id' not in session else redirect(url_for('clientes_view'))

@app.route("/clientes")
def clientes_view():
    return render_template("index.html") if 'user_id' in session else redirect(url_for('login_view'))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('login_view'))

# ====================================================================
# API
# ====================================================================
class UserRegister(Resource):
    def post(self):
        data = request.get_json(silent=True) or {}
        required = ['nome', 'login', 'senha', 'email', 'funcao']
        if not all(data.get(k) for k in required):
            return {"msg": "Todos os campos obrigatórios devem ser preenchidos."}, 400
        try:
            with get_sqlite_db() as conn:
                cur = conn.cursor()
                if cur.execute("SELECT 1 FROM usuarios WHERE login = ?", (data['login'],)).fetchone():
                    return {"msg": "Erro: Login já existe."}, 409

                senha_hash = generate_password_hash(data['senha'])
                cur.execute(
                    "INSERT INTO usuarios (nome, login, email, senha, funcao) VALUES (?, ?, ?, ?, ?)",
                    (data['nome'], data['login'], data['email'], senha_hash, data['funcao'])
                )
                conn.commit()
            return {"msg": "Usuário cadastrado com sucesso!"}, 201
        except Exception as e:
            log.exception("Erro no cadastro")
            return {"msg": f"Erro interno ao registrar: {e}"}, 500

class Login(Resource):
    def post(self):
        data = request.get_json(silent=True) or {}
        if not data.get("login") or not data.get("senha"):
            return {"msg": "Login e senha são obrigatórios."}, 400
        try:
            with get_sqlite_db() as conn:
                user = conn.execute(
                    "SELECT id, nome, senha FROM usuarios WHERE login = ?",
                    (data["login"],)
                ).fetchone()

                if not user:
                    return {"msg": "Usuário ou senha inválidos."}, 401

                senha_db = user["senha"]
                ok = check_password_hash(senha_db, data["senha"]) if senha_db.startswith("pbkdf2:") else (senha_db == data["senha"])
                if not ok:
                    return {"msg": "Usuário ou senha inválidos."}, 401

                session["user_id"] = user["id"]
                session["user_name"] = user["nome"]
                return {"msg": "Login realizado com sucesso."}, 200
        except Exception as e:
            log.exception("Erro no login")
            return {"msg": f"Erro interno no login: {e}"}, 500

class ListarClientes(Resource):
    def get(self):
        # limit
        try:
            limit_req = int(request.args.get("limit", 10))
            limit = min(app.config["MAX_PAGE_SIZE"], max(1, limit_req))
        except ValueError:
            return {"msg": "Parâmetro 'limit' inválido."}, 400

        # timeout por request (ms) ou default
        try:
            req_timeout = request.args.get("timeout")
            timeout_ms = int(req_timeout) if req_timeout else app.config["ORACLE_CALL_TIMEOUT_MS"]
        except ValueError:
            return {"msg": "Parâmetro 'timeout' inválido."}, 400

        index_hint = app.config["ORACLE_INDEX_HINT"]
        hint = f"/*+ FIRST_ROWS({limit}) {index_hint} */" if index_hint else f"/*+ FIRST_ROWS({limit}) */"

        try:
            with get_oracle_conn(call_timeout_ms=timeout_ms) as conn:
                cur = conn.cursor()
                cur.prefetchrows = limit
                cur.arraysize = limit

                sql = f"""
                    SELECT * FROM (
                        SELECT {hint}
                               CONTRATO, MATRICULA, COMPETENCIA_PAGAMENTO, BENEFICIARIO, VALOR
                        FROM {app.config['ORACLE_TABLE_CLIENTES']} u
                        ORDER BY DATPROCESSAMENTO DESC NULLS LAST, SEQUENCIA DESC NULLS LAST
                    )
                    WHERE ROWNUM <= :limit
                """
                cur.execute(sql, {"limit": limit})
                cols = [d[0] for d in cur.description]
                rows = [row_to_dict(cols, r) for r in cur.fetchall()]
                log.info(f"/api/clientes -> limit={limit} retornados={len(rows)} timeout_ms={timeout_ms}")
                return {"clientes": rows, "page": 1, "limit": limit, "total": 0}, 200

        except oracledb.Error as e:
            msg = str(e)
            # Timeouts/cancelamentos típicos
            if ("DPY-4024" in msg) or ("DPI-1067" in msg) or ("ORA-03156" in msg) or ("timeout" in msg.lower()):
                log.warning(f"/api/clientes timeout/cancel: {msg}")
                return {"msg": "Tempo excedido ao consultar o Oracle."}, 504
            log.exception("Erro ao listar clientes")
            return {"msg": f"Erro ao buscar clientes no Oracle: {msg}"}, 500
        except Exception as e:
            log.exception("Erro ao listar clientes")
            return {"msg": f"Erro ao buscar clientes no Oracle: {e}"}, 500

class BuscarUltimoCadastro(Resource):
    def get(self):
        matricula = request.args.get("matricula")
        if not matricula:
            return {"msg": "Matrícula não fornecida."}, 400

        try:
            with get_oracle_conn(call_timeout_ms=app.config["ORACLE_CALL_TIMEOUT_MS"]) as conn:
                cur = conn.cursor()
                sql = f"""
                    WITH CANDIDATOS AS (
                        SELECT u.*,
                               ROW_NUMBER() OVER (
                                   ORDER BY
                                       CASE
                                         WHEN TRANSLATE(UPPER(TRIM(u.TIPO_ATENDIMENTO)),
                                             UNISTR('\\00C7\\00C3\\00C2\\00C1\\00C0\\00D5'), 'CAAAAO') = 'REMOCAO'
                                         THEN 0 ELSE 1 END,
                                       u.COMPETENCIA_PROCESSAMENTO DESC NULLS LAST,
                                       u.SEQUENCIA DESC NULLS LAST
                               ) AS RN
                        FROM {app.config['ORACLE_TABLE_CLIENTES']} u
                        WHERE u.MATRICULA = :matricula
                    ),
                    MAX_GERAL AS (
                        SELECT MAX(SEQUENCIA) AS SEQUENCIA_GERAL
                        FROM {app.config['ORACLE_TABLE_CLIENTES']}
                    )
                    SELECT
                        NVL(MAX_GERAL.SEQUENCIA_GERAL, 0) AS SEQUENCIA_GERAL,
                        NVL(MAX_GERAL.SEQUENCIA_GERAL, 0) + 1 AS PROXIMA_SEQUENCIA,
                        ULTIMO.*
                    FROM MAX_GERAL
                    LEFT JOIN (SELECT * FROM CANDIDATOS WHERE RN = 1) ULTIMO ON 1 = 1
                """
                cur.prefetchrows = 2
                cur.arraysize = 2
                cur.execute(sql, {"matricula": matricula})
                row = cur.fetchone()

                data = {"MATRICULA": matricula}
                if row:
                    cols = [d[0] for d in cur.description]
                    row_dict = row_to_dict(cols, row)
                    data.update(row_dict)

                data = apply_business_defaults({k.upper(): v for k, v in data.items()})
                msg = "Dados encontrados." if len(data.keys()) > 0 else "Nenhum cadastro anterior."
                return {"msg": msg, "data": data}, 200

        except oracledb.Error as e:
            msg = str(e)
            if ("DPY-4024" in msg) or ("DPI-1067" in msg) or ("ORA-03156" in msg) or ("timeout" in msg.lower()):
                return {"msg": "Tempo excedido ao consultar o Oracle."}, 504
            log.exception("Erro no último cadastro")
            return {"msg": f"Erro ao buscar cadastro: {msg}"}, 500
        except Exception as e:
            log.exception("Erro no último cadastro")
            return {"msg": f"Erro ao buscar cadastro: {e}"}, 500

class CadastrarCliente(Resource):
    def post(self):
        auth = require_login()
        if auth:
            return auth

        payload = request.get_json(silent=True) or {}
        if not payload:
            return {"msg": "Nenhum dado recebido."}, 400

        try:
            metadata = get_oracle_table_metadata()
            if not metadata:
                return {"msg": "Nao foi possivel obter os metadados da tabela Oracle."}, 500

            incoming = OrderedDict()
            for key, value in payload.items():
                if not isinstance(key, str):
                    continue
                col = key.upper()
                if col in metadata:
                    incoming[col] = value

            incoming = apply_business_defaults(incoming)

            if "SEQUENCIA" not in incoming or incoming["SEQUENCIA"] in ("", None):
                with get_oracle_conn(call_timeout_ms=app.config["ORACLE_CALL_TIMEOUT_MS"]) as conn:
                    incoming["SEQUENCIA"] = get_next_global_sequence(conn)

            if "DATPROCESSAMENTO" not in incoming or incoming["DATPROCESSAMENTO"] in ("", None):
                incoming["DATPROCESSAMENTO"] = _today_yyyy_mm_dd()

            normalized = OrderedDict()
            for column, value in incoming.items():
                try:
                    normalized[column] = normalize_bind_value(column, value, metadata.get(column))
                except ValueError as exc:
                    return {"msg": f"Valor invalido para {column}: {exc}"}, 400

            required_columns = [col for col, info in metadata.items() if not info.get("nullable")]
            missing = [col for col in required_columns if normalized.get(col) is None]
            if missing:
                log.debug(f"Campos obrigatorios ausentes: {missing}")
                return {"msg": "Preencha os campos obrigatorios antes de salvar.", "missing": missing}, 400

            ordered_columns = [col for col in metadata.keys() if col in normalized]
            normalized = OrderedDict((col, normalized[col]) for col in ordered_columns)

            col_names = ", ".join(normalized.keys())
            binds = ", ".join(f":{col}" for col in normalized.keys())
            sql = f"INSERT INTO {app.config['ORACLE_TABLE_CLIENTES']} ({col_names}) VALUES ({binds})"

            with get_oracle_conn(call_timeout_ms=app.config["ORACLE_CALL_TIMEOUT_MS"]) as conn:
                cur = conn.cursor()
                cur.execute(sql, normalized)
                conn.commit()

            return {"msg": "Cliente cadastrado com sucesso!"}, 201

        except oracledb.Error as e:
            msg = str(e)
            if ("DPY-4024" in msg) or ("DPI-1067" in msg) or ("ORA-03156" in msg) or ("timeout" in msg.lower()):
                return {"msg": "Tempo excedido ao salvar no Oracle."}, 504
            log.exception("Erro ao cadastrar cliente")
            return {"msg": f"Erro ao salvar cliente no Oracle: {msg}"}, 500
        except Exception as e:
            log.exception("Erro ao cadastrar cliente")
            return {"msg": f"Erro ao salvar cliente no Oracle: {e}"}, 500

# ====================================================================
# ENDPOINTS / HEALTH
# ====================================================================
api.add_resource(Login, '/api/login')
api.add_resource(UserRegister, '/api/cadastro')
api.add_resource(ListarClientes, '/api/clientes')
api.add_resource(CadastrarCliente, '/api/cadastrar-cliente')
api.add_resource(BuscarUltimoCadastro, '/api/ultimo-cadastro-por-matricula')

@app.route("/healthz")
def healthz():
    info = {
        "sqlite_ok": False,
        "oracle_ok": False,
        "thick": None,
        "clientversion": None,
        "dsn": f"{app.config['ORACLE_HOST']}:{app.config['ORACLE_PORT']}/{app.config['ORACLE_SERVICE']}",
        "pool": {
            "min": app.config["ORACLE_POOL_MIN"],
            "max": app.config["ORACLE_POOL_MAX"],
            "inc": app.config["ORACLE_POOL_INC"],
            "stmt_cache": app.config["ORACLE_STMT_CACHE"],
        }
    }
    try:
        with get_sqlite_db() as c:
            c.execute("SELECT 1")
        info["sqlite_ok"] = True
    except Exception as e:
        return jsonify({"ok": False, "where": "sqlite", "err": str(e), "info": info}), 500

    try:
        cv = oracledb.clientversion()
        info["clientversion"] = ".".join(map(str, cv)) if cv else None
        info["thick"] = bool(cv and any(cv))

        with get_oracle_conn(call_timeout_ms=3000) as conn:
            cur = conn.cursor()
            cur.execute("SELECT 1 FROM DUAL")
        info["oracle_ok"] = True
        return jsonify({"ok": True, "info": info})
    except Exception as e:
        return jsonify({"ok": False, "where": "oracle", "err": str(e), "info": info}), 500

if __name__ == "__main__":
    get_oracle_table_columns()
    get_oracle_table_metadata()
    app.run(debug=True, host="0.0.0.0")
