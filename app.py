                       
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, Response, send_from_directory
from flask_restful import Api, Resource
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from collections import OrderedDict
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
import logging
import io
import csv
import os
import sys
import platform
import sqlite3
import oracledb
import time  

load_dotenv()
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO))
log = logging.getLogger("app")
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
    _DEFAULT_IC_DIR = os.path.join(
        BASE_DIR,
        "instantclient-basic-windows.x64-23.9.0.25.07",
        "instantclient_23_9",
    )
    ORACLE_THICK_LIB_DIR = os.getenv(
        "ORACLE_THICK_LIB_DIR",
        _DEFAULT_IC_DIR if os.path.isdir(_DEFAULT_IC_DIR) else ""
    )

    ORACLE_TABLE_CLIENTES = os.getenv("ORACLE_TABLE_CLIENTES", "UNI0177_TBTIPOGUIA_REMOCAO")

    MAX_PAGE_SIZE = int(os.getenv("MAX_PAGE_SIZE", "100"))

                                  
    ORACLE_POOL_MIN = int(os.getenv("ORACLE_POOL_MIN", "1"))
    ORACLE_POOL_MAX = int(os.getenv("ORACLE_POOL_MAX", "5"))
    ORACLE_POOL_INC = int(os.getenv("ORACLE_POOL_INC", "1"))
    ORACLE_CALL_TIMEOUT_MS = int(os.getenv("ORACLE_CALL_TIMEOUT_MS", "20000"))       
    ORACLE_STMT_CACHE = int(os.getenv("ORACLE_STMT_CACHE", "100"))

    
    ORACLE_INDEX_HINT = os.getenv("ORACLE_INDEX_HINT", "").strip()

    
    ORACLE_CLIENTES_DEFAULT_DAYS = int(os.getenv("ORACLE_CLIENTES_DEFAULT_DAYS", "14"))
    ORACLE_CLIENTES_FALLBACK_DAYS = int(os.getenv("ORACLE_CLIENTES_FALLBACK_DAYS", "7"))

    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"
    SESSION_TTL_MINUTES = int(os.getenv("SESSION_TTL_MIN", "30"))

_ENV_THICK = os.getenv("ORACLE_USE_THICK")
if _ENV_THICK is None:
    REQUIRE_ORACLE_THICK = bool(Config.ORACLE_THICK_LIB_DIR)
else:
    REQUIRE_ORACLE_THICK = _ENV_THICK.lower() == "true"
    if REQUIRE_ORACLE_THICK and not os.getenv("ORACLE_THICK_LIB_DIR"):
                                                                                          
        if os.path.isdir(Config.ORACLE_THICK_LIB_DIR):
            os.environ["ORACLE_THICK_LIB_DIR"] = Config.ORACLE_THICK_LIB_DIR
_THICK_INITIALIZED = False

app = Flask(__name__)
app.config.from_object(Config)
api = Api(app)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=app.config["SESSION_COOKIE_SECURE"],
    JSON_AS_ASCII=False,
)
app.permanent_session_lifetime = timedelta(minutes=app.config.get("SESSION_TTL_MINUTES", 30))

def _enable_thick_mode_once():
    global _THICK_INITIALIZED
    if _THICK_INITIALIZED:
        return
    _init_oracle_thick_or_fail()
    _THICK_INITIALIZED = True
    log.info("Oracle THICK habilitado.")

@app.after_request
def _sec_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    if resp.mimetype == "text/html" and "charset" not in (resp.content_type or "").lower():
        resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


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


def _assert_64bit():
    arch, _ = platform.architecture()
    if arch != "64bit":
        raise RuntimeError("Python precisa ser 64-bit para usar Oracle Client 64-bit (THICK).")

def _instant_client_probe(lib_dir: str):
    if not lib_dir or not os.path.isdir(lib_dir):
        log.error(f"ORACLE_THICK_LIB_DIR ('{lib_dir}') não é uma pasta válida.")
        raise RuntimeError(
            "ORACLE_THICK_LIB_DIR nao configurado ou pasta invalida. "
            "Defina a pasta do Instant Client 64-bit (ex.: C:\\oracle\\instantclient_23_9)."
        )
    log.info(f"Verificando Instant Client em: {lib_dir}")
    if os.name == "nt":
        oci = os.path.join(lib_dir, "oci.dll")
        if not os.path.isfile(oci):
            log.error(f"oci.dll não encontrado em '{lib_dir}'.")
            raise RuntimeError(
                f"Instant Client invalido: nÃ£o encontrei oci.dll em '{lib_dir}'. "
                "Aponte para a subpasta instantclient_XX_X."
            )
        log.info(f"oci.dll encontrado em '{oci}'.")
        try:
            log.info(f"Adicionando '{lib_dir}' ao search path de DLLs.")
            os.add_dll_directory(lib_dir)
        except Exception as e:
            log.warning(f"Falha ao chamar os.add_dll_directory('{lib_dir}'): {e}. Isso pode ser ignorado em alguns sistemas.")
            pass
        if lib_dir not in os.environ.get("PATH", ""):
            log.info(f"Adicionando '{lib_dir}' à variável de ambiente PATH.")
            os.environ["PATH"] = lib_dir + os.pathsep + os.environ.get("PATH", "")
        else:
            log.info(f"'{lib_dir}' já está no PATH.")
    elif sys.platform.startswith("linux"):
        so = os.path.join(lib_dir, "libclntsh.so")
        if not os.path.isfile(so):
            raise RuntimeError(f"Instant Client invÃ¡lido: nÃ£o encontrei libclntsh.so em '{lib_dir}'.")
    elif sys.platform == "darwin":
        dylib = os.path.join(lib_dir, "libclntsh.dylib")
        if not os.path.isfile(dylib):
            raise RuntimeError(f"Instant Client invÃ¡lido: nÃ£o encontrei libclntsh.dylib em '{lib_dir}'.")

def _init_oracle_thick_or_fail():
    log.info("Iniciando tentativa de habilitação do modo THICK...")
    _assert_64bit()
    lib_dir = _norm_path_env("ORACLE_THICK_LIB_DIR") or app.config["ORACLE_THICK_LIB_DIR"]
    lib_dir = _strip_quotes(lib_dir) or ""
    _instant_client_probe(lib_dir)

    net_admin = _strip_quotes(os.getenv("ORACLE_NET_ADMIN") or "")
    try:
        log.info(f"Chamando oracledb.init_oracle_client(lib_dir='{lib_dir}', config_dir='{net_admin or 'None'}')")
        if net_admin and os.path.isdir(net_admin):
            oracledb.init_oracle_client(lib_dir=lib_dir, config_dir=net_admin)
        else:
            oracledb.init_oracle_client(lib_dir=lib_dir)
        
                                                        
        cv = oracledb.clientversion()
        if not any(cv):
             log.warning("oracledb.init_oracle_client() foi chamado, mas o driver ainda reporta modo THIN.")
        else:
             log.info(f"oracledb.init_oracle_client() bem-sucedido. Versão do cliente: {'.'.join(map(str, cv))}")

    except Exception as e:
        log.error(f"Falha CRÍTICA ao iniciar Oracle THICK com lib_dir='{lib_dir}': {e}", exc_info=True)
        raise RuntimeError(
            f"Falha ao iniciar Oracle THICK: {e}. Cheque Instant Client 64-bit, oci.dll e Microsoft VC++ x64."
        ) from e


if REQUIRE_ORACLE_THICK:
    log.info("ORACLE_USE_THICK=true detectado. Forçando inicialização do modo THICK.")
    _enable_thick_mode_once()                                                            
else:
    log.info("Oracle THIN habilitado (Instant Client opcional).")

ORACLE_DSN = oracledb.makedsn(
    host=app.config["ORACLE_HOST"],
    port=app.config["ORACLE_PORT"],
    service_name=app.config["ORACLE_SERVICE"],
)

POOL = None

def _make_pool():
    if REQUIRE_ORACLE_THICK and not _THICK_INITIALIZED:
        _enable_thick_mode_once()

    def _create():
        return oracledb.create_pool(
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

    try:
        return _create()
    except oracledb.Error as exc:
        msg = str(exc)
        needs_thick = "DPY-3001" in msg or "Native Network Encryption" in msg
        if needs_thick and not _THICK_INITIALIZED:
            log.warning(
                "Oracle exigiu Native Network Encryption; tentando habilitar modo THICK automaticamente..."
            )
            try:
                _enable_thick_mode_once()
                return _create()
            except Exception as thick_exc:
                raise RuntimeError(
                    "Native Network Encryption exige o modo THICK, porém não foi possível inicializar o Oracle Client. "
                    "Verifique ORACLE_THICK_LIB_DIR/Instant Client 64-bit e Microsoft VC++ x64."
                ) from thick_exc

        raise

def _build_date_filter(available_cols, days_window: int | None):
    filters = []
    params = {}
    if days_window and "DATPROCESSAMENTO" in available_cols:
        min_date = datetime.now(timezone.utc) - timedelta(days=days_window)
        filters.append("u.DATPROCESSAMENTO >= :min_dataproc")
        params["min_dataproc"] = min_date
    return filters, params

def _get_pool():
    global POOL
    if POOL is None:
        POOL = _make_pool()
    return POOL

@contextmanager
def get_oracle_conn(call_timeout_ms: int | None = None):
    """Obtém uma conexão do pool, gerencia seu ciclo de vida e define o timeout."""
    conn = None
    try:
        conn = _get_pool().acquire()
        if call_timeout_ms:
                                                           
            conn.call_timeout = int(call_timeout_ms)
        yield conn
    finally:
        if conn:
            try:
                                           
                conn.close()
            except Exception:
                pass                                   

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
    """Busca metadados incluindo comprimento de colunas para evitar ORA-12899."""
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
                    SELECT column_name,
                           data_type,
                           data_precision,
                           data_scale,
                           nullable,
                           column_id,
                           data_length,
                           char_col_decl_length
                    FROM all_tab_columns
                    WHERE owner = :p_owner AND table_name = :p_table
                    ORDER BY column_id
                    """,
                    {"p_owner": owner, "p_table": table},
                )
            else:
                cur.execute(
                    """
                    SELECT column_name,
                           data_type,
                           data_precision,
                           data_scale,
                           nullable,
                           column_id,
                           data_length,
                           char_col_decl_length
                    FROM user_tab_columns
                    WHERE table_name = :p_table
                    ORDER BY column_id
                    """,
                    {"p_table": table},
                )
            for name, dtype, precision, scale, nullable, col_id, data_length, char_len in cur:
                meta[name.upper()] = {
                    "data_type": (dtype or "").upper(),
                    "data_precision": precision,
                    "data_scale": scale,
                    "nullable": (nullable or "Y") == "Y",
                    "column_id": col_id,
                    "data_length": data_length,
                    "char_length": char_len,
                }
    except Exception as e:
        log.error(f"Erro ao buscar metadados da tabela Oracle: {e}")
        meta = OrderedDict()

    _ORACLE_TABLE_METADATA = meta
    return _ORACLE_TABLE_METADATA

def _col_dtype(col: str) -> str:
    meta = get_oracle_table_metadata()
    return (meta.get(col.upper(), {}).get("data_type") or "").upper()

                                                                      
                                     
                                                                      
def _today_yyyy_mm_dd():
    return date.today().isoformat()

def _yyyy_mm_now():
    d = date.today()
    return f"{d.year}{d.month:02d}"

def _as_yyyymm_str(v) -> str:
    """Normaliza qualquer entrada (date/datetime/int/str) para 'YYYYMM'."""
    if isinstance(v, (date, datetime)):
        return f"{v.year}{v.month:02d}"
    s = str(v or "").strip()
    if s.isdigit():
        if len(s) >= 6:
            return s[:6]
        if len(s) == 4:
                                              
            d = date.today()
            return f"{s}{d.month:02d}"
                            
    s2 = "".join(ch for ch in s if ch.isdigit())
    if len(s2) >= 6:
        return s2[:6]
    return _yyyy_mm_now()

def _as_char1(v, default=""):
    """ForÃ§a colunas CHAR(1)/flags para 1 caractere maiÃºsculo."""
    s = (str(v or default).strip() or default)
    return s[:1].upper() if s else ""

def normalize_bind_value(column, value, meta):
    """Normaliza Python -> tipo Oracle respeitando DDL (tamanho, escala, CHAR(1), YYYYMM etc)."""
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
    col = (column or "").upper()

                                    
    if col == "COMPETENCIA_PAGAMENTO":                                    
        value = _as_yyyymm_str(value)
    if col == "COMPETENCIA_PROCESSAMENTO":                                   
        value = int(_as_yyyymm_str(value))
    if col in {"TP_GUIA", "NC", "CARATER_ATENDIMENTO"}:
        value = _as_char1(value)

    if dtype in {"CHAR", "NCHAR", "VARCHAR2", "NVARCHAR2", "CLOB"}:
        out = str(value)
                                                           
        maxlen = meta.get("char_length") or meta.get("data_length")
        if maxlen and len(out) > int(maxlen):
            out = out[: int(maxlen)]
        return out

    if dtype in {"DATE", "TIMESTAMP", "TIMESTAMP(6)",
                 "TIMESTAMP WITH TIME ZONE", "TIMESTAMP WITH LOCAL TIME ZONE"}:
        if isinstance(value, datetime):
            return value
        if isinstance(value, date):
            return datetime.combine(value, datetime.min.time())
        if isinstance(value, str):
            candidate = value.replace("Z", "")
            try:
                                                             
                return datetime.fromisoformat(candidate)
            except ValueError:
                for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%Y%m%d"):
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
        precision = meta.get("data_precision")

                                      
        if scale is not None:
            q = Decimal(1).scaleb(-int(scale))             
            try:
                decimal_value = decimal_value.quantize(q)
            except Exception:
                pass

                                                 
        if (scale is None or int(scale) == 0) and decimal_value == decimal_value.to_integral_value():
            out = int(decimal_value)
        else:
            out = decimal_value

                                                                        
                                   
                                                                                  
                                                                              

        return out

    return value

                                                                      
                    
                                                                      
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

def is_timeout_error(msg: str) -> bool:
    if not msg:
        return False
    m = msg.lower()
    return ("dpy-4024" in m) or ("dpi-1067" in m) or ("ora-03156" in m) or ("timeout" in m)

                                                                      
                                                   
                                                                      
BUSINESS_DEFAULTS = {
    "DATPROCESSAMENTO": _today_yyyy_mm_dd,                    
    "COMPETENCIA_PAGAMENTO": _yyyy_mm_now,                                    
    "COMPETENCIA_PROCESSAMENTO": _yyyy_mm_now,                            
    "TP_GUIA": "P",                                      
    "TIP_GUIA": "REMOCAO",
    "TP_ITEM": "Taxa",
    "SEQ": 1,                                            
    "DATA_EXECUCAO": _today_yyyy_mm_dd,
    "LOCALIDADE": "LOCAL",
    "TIP_FOR": "REM",
    "NC": "S",                                          
    "TIPO_LANCAMENTO": "PRODUCAO - REMOCAO",
    "CAPITULO": "TAXA",
    "GRUPO": "TAXA",
    "SUBGRUPO": "TAXA",
    "PARTICIPACAO": "SEM PARTICIPACAO",
    "UNIMED": "LOCAL",
    "VAL_FAT": Decimal("0"),                                          
    "FAT_NRO": 0,                                                   
    "UNI_COD_RESPON": 177,                                         
    "PARAMETRO_INT": Decimal("0"),                                    
    "PARAMETRO_LOC": Decimal("0"),                                    
    "TIPO_ATENDIMENTO": "REMOCAO",
    "CARATER_ATENDIMENTO": "E",
    "ORIGEM_REDE": "OUTRA OPERADORA",
}

def apply_business_defaults(record: dict) -> dict:
    out = dict(record or {})
    for key, default in BUSINESS_DEFAULTS.items():
        if key not in out or out[key] in ("", None):
            out[key] = default() if callable(default) else default

                          
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


@app.route("/favicon.ico")
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, "static", "img"),
        "aviao.png",
        mimetype="image/png"
    )

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('login_view'))

                                                                      
     
                                                                      
class UserRegister(Resource):
    def post(self):
        data = request.get_json(silent=True) or {}
        required = ['nome', 'login', 'senha', 'email', 'funcao']
        if not all(data.get(k) for k in required):
            return {"msg": "Todos os campos obrigatorios devem ser preenchidos."}, 400
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
            return {"msg": "UsuÃ¡rio cadastrado com sucesso!"}, 201
        except Exception as e:
            log.exception("Erro no cadastro")
            return {"msg": f"Erro interno ao registrar: {e}"}, 500

class Login(Resource):
    def post(self):
        data = request.get_json(silent=True) or {}
        if not data.get("login") or not data.get("senha"):
            return {"msg": "Login e senha sÃ£o obrigadotorios."}, 400
        try:
            with get_sqlite_db() as conn:
                user = conn.execute(
                    "SELECT id, nome, senha FROM usuarios WHERE login = ?",
                    (data["login"],)
                ).fetchone()

                if not user:
                    return {"msg": "Usuario ou senha invalidos."}, 401

                senha_db = user["senha"]
                ok = check_password_hash(senha_db, data["senha"]) if senha_db.startswith("pbkdf2:") else (senha_db == data["senha"])
                if not ok:
                    return {"msg": "Usuario ou senha Invalido."}, 401

                session["user_id"] = user["id"]
                session["user_name"] = user["nome"]
                return {"msg": "Login realizado com sucesso."}, 200
        except Exception as e:
            log.exception("Erro no login")
            return {"msg": f"Erro interno no login: {e}"}, 500

class ListarClientes(Resource):
    EXPECTED_COLUMNS = ["CONTRATO","MATRICULA","COMPETENCIA_PAGAMENTO","BENEFICIARIO","VALOR"]

    def _run_paginated_query(self, conn, page: int, limit: int, hint: str, competencia_exact: str | None, competencia_min: str | None):
        offset = (page - 1) * limit
        select_list = ", ".join(f"u.{col}" for col in self.EXPECTED_COLUMNS)
        order_clause = "ORDER BY u.COMPETENCIA_PAGAMENTO DESC NULLS LAST"
        params = {"offset": offset, "limit": limit}
        where_clause = ""
        if competencia_exact:
            where_clause = "WHERE u.COMPETENCIA_PAGAMENTO = :competencia"
            params["competencia"] = competencia_exact
        elif competencia_min:
            where_clause = "WHERE u.COMPETENCIA_PAGAMENTO >= :min_comp"
            params["min_comp"] = competencia_min

        sql = f"""
            SELECT {hint} {select_list}
            FROM {app.config['ORACLE_TABLE_CLIENTES']} u
            {where_clause}
            {order_clause}
            OFFSET :offset ROWS FETCH NEXT :limit ROWS ONLY
        """
        cur = conn.cursor()
        cur.execute(sql, params)
        rows = [row_to_dict(self.EXPECTED_COLUMNS, row) for row in cur.fetchall()]
        if len(rows) < limit:
            total = offset + len(rows)
        else:
            total = offset + len(rows) + 1
        return rows, total

    def get(self):
        try:
            page_req = int(request.args.get("page", 1))
            limit_req = int(request.args.get("limit", 10))
            page = max(1, page_req)
            limit = min(app.config["MAX_PAGE_SIZE"], max(1, limit_req))
        except ValueError:
            return {"msg": "Parâmetros 'page' ou 'limit' inválidos."}, 400

        try:
            req_timeout = request.args.get("timeout")
                                                            
            timeout_ms = int(req_timeout) if req_timeout else app.config["ORACLE_CALL_TIMEOUT_MS"]
        except (ValueError, TypeError):
            timeout_ms = app.config["ORACLE_CALL_TIMEOUT_MS"]

        index_hint = app.config["ORACLE_INDEX_HINT"]
        hint = f"/*+ {index_hint} */" if index_hint else ""
        competencia_param = request.args.get("competencia_from")
        if competencia_param:
            competencia_exact = competencia_param.strip()[:6]
            competencia_min = None
        else:
            days = app.config.get("ORACLE_CLIENTES_DEFAULT_DAYS")
            if days:
                cutoff = datetime.now().date() - timedelta(days=days)
                competencia_min = f"{cutoff.year}{cutoff.month:02d}"
                competencia_exact = None
            else:
                competencia_min = None
                competencia_exact = None
        try:
            with get_oracle_conn(call_timeout_ms=timeout_ms) as conn:
                rows, total = self._run_paginated_query(conn, page, limit, hint, competencia_exact, competencia_min)
                return {"clientes": rows, "page": page, "limit": limit, "total": total}, 200

        except oracledb.Error as e:
            msg = str(e)
            if is_timeout_error(msg):
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
            return {"msg": "Matricula não fornecida."}, 400

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
                t0 = time.perf_counter()
                cur.execute(sql, {"matricula": matricula})
                row = cur.fetchone()
                log.debug(f"/api/ultimo-cadastro-por-matricula exec {(time.perf_counter() - t0)*1000:.1f} ms")

                data = {"MATRICULA": matricula}
                if row:
                    cols = [d[0] for d in cur.description]
                    row_dict = row_to_dict(cols, row)
                    data.update(row_dict)

                data = apply_business_defaults({k.upper(): v for k, v in data.items()})
                msg = "Dados encontrados." if len(data.keys()) > 0 else "Nenhum cadastro anterior."
                safe_data = {k: sanitize(v) for k, v in data.items()}
                return {"msg": msg, "data": safe_data}, 200

        except oracledb.Error as e:
            msg = str(e)
            if is_timeout_error(msg):
                return {"msg": "Tempo excedido ao consultar o Oracle."}, 504
            log.exception("Erro no ultimo cadastro")
            return {"msg": f"Erro ao buscar cadastro: {msg}"}, 500
        except Exception as e:
            log.exception("Erro no ultimo cadastro")
            return {"msg": f"Erro ao buscar cadastro: {e}"}, 500

class CadastrarCliente(Resource):
    def post(self):
        auth = require_login()
        if auth:
            return auth

        payload = request.get_json(silent=True)
        if not payload:
            try:
                form_dict = {k: v for k, v in request.form.items()}
                if not form_dict:
                    form_dict = {k: v for k, v in request.args.items()}
                payload = form_dict
            except Exception:
                payload = {}
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

                                               
            incoming["DATPROCESSAMENTO"] = incoming.get("DATPROCESSAMENTO") or _today_yyyy_mm_dd()
            incoming["COMPETENCIA_PAGAMENTO"] = _as_yyyymm_str(incoming.get("COMPETENCIA_PAGAMENTO") or _yyyy_mm_now())
            incoming["COMPETENCIA_PROCESSAMENTO"] = int(_as_yyyymm_str(incoming.get("COMPETENCIA_PROCESSAMENTO") or _yyyy_mm_now()))

                                                                                                                     
            matricula_val = (incoming.get("MATRICULA") or "").strip()
            try:
                if matricula_val:
                    with get_oracle_conn(call_timeout_ms=app.config["ORACLE_CALL_TIMEOUT_MS"]) as conn:
                        cur = conn.cursor()
                        sql_auto = f"""
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
                            )
                            SELECT * FROM CANDIDATOS WHERE RN = 1
                        """
                        cur.prefetchrows = 1
                        cur.arraysize = 1
                        cur.execute(sql_auto, {"matricula": matricula_val})
                        row = cur.fetchone()
                        if row:
                            cols = [d[0] for d in cur.description]
                            last_rec = row_to_dict(cols, row)
                        else:
                            last_rec = {}
                    for k in ("CONTRATO", "COD_CNTRAT_CART", "COD", "COD_DEPNTE", "BENEFICIARIO"):
                        if incoming.get(k) in (None, "") and last_rec.get(k) not in (None, ""):
                            incoming[k] = last_rec.get(k)
            except Exception:
                pass

                           
            for k in ("TP_GUIA", "NC", "CARATER_ATENDIMENTO"):
                incoming[k] = _as_char1(incoming.get(k), default=BUSINESS_DEFAULTS.get(k, "")) or None

                                              
            for k, v in {
                "VAL_FAT": Decimal("0"),
                "FAT_NRO": 0,
                "PARAMETRO_INT": Decimal("0"),
                "PARAMETRO_LOC": Decimal("0"),
                "UNI_COD_RESPON": 177,
            }.items():
                if incoming.get(k) in (None, ""):
                    incoming[k] = v

                                                                      
            if "GUIA_COD_ID" in metadata and not incoming.get("GUIA_COD_ID"):
                return {"msg": "Preencha o campo obrigatório GUIA_COD_ID."}, 400

                                                            
            if not incoming.get("ITEM_COD"):
                return {"msg": "Informe o ITEM_COD (obrigadotorios)."}, 400

                                                  
                                                                     
            business_required = [
                "MATRICULA","COD","CONTRATO","GUIA_COD_ID","VALOR","QTDE","UNIMED_EXEC",
                "INDICACAO_CLINICA","FORNECEDOR","IDADE","GUIA_COD","GUIA_COD_PREST","NOME_PREST",
                "COD_CNTRAT_CART","COD_DEPNTE","BENEFICIARIO",
                                               
                "ITEM_COD",
            ]
            missing_business = [k for k in business_required if incoming.get(k) in (None, "")]
            if missing_business:
                return {"msg": f"Preencha os campos obrigatórios: {', '.join(missing_business)}"}, 400

                                                  
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
                return {"msg": f"Campos obrigatórios do banco de dados estão faltando: {', '.join(missing)}"}, 400

                                                   
            ordered_columns = [col for col in metadata.keys() if col in normalized]
            normalized = OrderedDict((col, normalized[col]) for col in ordered_columns)

            col_names = ", ".join(normalized.keys())
            binds = ", ".join(f":{col}" for col in normalized.keys())
            sql = f"INSERT INTO {app.config['ORACLE_TABLE_CLIENTES']} ({col_names}) VALUES ({binds})"

            with get_oracle_conn(call_timeout_ms=app.config["ORACLE_CALL_TIMEOUT_MS"]) as conn:
                cur = conn.cursor()
                t0 = time.perf_counter()
                cur.execute(sql, normalized)
                conn.commit()
                log.debug(f"/api/cadastrar-cliente exec {(time.perf_counter() - t0)*1000:.1f} ms")

            return {"msg": "Cliente cadastrado com sucesso!"}, 201

        except oracledb.Error as e:
            msg = str(e)
            if is_timeout_error(msg):
                return {"msg": "Tempo excedido ao salvar no Oracle."}, 504
            log.exception("Erro ao cadastrar cliente")
            return {"msg": f"Erro ao salvar cliente no Oracle: {msg}"}, 500
        except Exception as e:
            log.exception("Erro ao cadastrar cliente")
            return {"msg": f"Erro ao salvar cliente no Oracle: {e}"}, 500

                                                                      
                    
                                                                      
api.add_resource(Login, '/api/login')
api.add_resource(UserRegister, '/api/cadastro')
api.add_resource(ListarClientes, '/api/clientes')
api.add_resource(CadastrarCliente, '/api/cadastrar-cliente')
api.add_resource(BuscarUltimoCadastro, '/api/ultimo-cadastro-por-matricula')
                                   
class ListarLogs(Resource):
    LOG_COLUMNS = [
        "DATPROCESSAMENTO",
        "GUIA_COD_ID",
        "GUIA_COD",
        "MATRICULA",
        "BENEFICIARIO",
        "VALOR",
        "TIPO_ATENDIMENTO",
    ]

    def _fetch_logs(self, conn, start, end, limit, hint):
        cur = conn.cursor()
        select_list = ", ".join(f"u.{col}" for col in self.LOG_COLUMNS)
        sql = f"""
            SELECT * FROM (
              SELECT {hint} {select_list}
              FROM {app.config['ORACLE_TABLE_CLIENTES']} u
              WHERE u.DATPROCESSAMENTO >= :p_start AND u.DATPROCESSAMENTO < :p_end
              ORDER BY u.DATPROCESSAMENTO DESC, u.GUIA_COD_ID DESC
            )
            WHERE ROWNUM <= :p_limit
        """
        cur.prefetchrows = min(1000, limit)
        cur.arraysize = min(1000, limit)
        cur.execute(sql, {"p_start": start, "p_end": end, "p_limit": limit})
        rows = [row_to_dict(self.LOG_COLUMNS, r) for r in cur.fetchall()]
        return self.LOG_COLUMNS, rows

    def get(self):
        auth = require_login()
        if auth:
            return auth

        date_param = request.args.get("date") or request.args.get("datprocessamento") or request.args.get("data")
        if not date_param:
            return {"msg": "Informe a data (YYYY-MM-DD)."}, 400
                                                                                           
        try:
            dt = normalize_bind_value("DATPROCESSAMENTO", date_param, {"data_type": "DATE"})
            d0 = dt.date()
            start = datetime(d0.year, d0.month, d0.day, 0, 0, 0)
            end = start + timedelta(days=1)
        except Exception:
            return {"msg": "Data invÃ¡lida."}, 400

                                                       
        try:
            req_timeout = request.args.get("timeout")
            timeout_ms = int(req_timeout) if req_timeout else max(app.config["ORACLE_CALL_TIMEOUT_MS"], 60000)
        except Exception:
            timeout_ms = max(app.config["ORACLE_CALL_TIMEOUT_MS"], 60000)

                                                                         
        try:
            limit = int(request.args.get("limit", "500"))
            limit = max(1, min(5000, limit))
        except Exception:
            limit = 500

        try:
            with get_oracle_conn(call_timeout_ms=timeout_ms) as conn:
                index_hint = app.config["ORACLE_INDEX_HINT"]
                hint = f"/*+ {index_hint} */" if index_hint else ""
                try:
                    cols, rows = self._fetch_logs(conn, start, end, limit, hint)
                    partial = False
                except oracledb.Error as e:
                    msg = str(e)
                    if is_timeout_error(msg) and limit > 100:
                        fallback_limit = max(100, min(250, limit // 2))
                        log.warning(
                            "Timeout ao buscar logs (limit=%s). Tentando novamente com limit=%s.",
                            limit,
                            fallback_limit,
                        )
                        cols, rows = self._fetch_logs(conn, start, end, fallback_limit, hint)
                        limit = fallback_limit
                        partial = True
                    else:
                        raise

                total = len(rows)
                response = {
                    "date": start.date().isoformat(),
                    "columns": cols,
                    "rows": rows,
                    "total": total,
                    "limit": limit,
                }
                if partial:
                    response["partial"] = True
                log.debug(f"/api/logs exec rows={total}, limit={limit}, partial={partial}")
                return response, 200
        except oracledb.Error as e:
            msg = str(e)
            if is_timeout_error(msg):
                return {"msg": "Tempo excedido ao consultar o Oracle."}, 504
            log.exception("Erro ao listar logs")
            return {"msg": f"Erro ao buscar logs no Oracle: {msg}"}, 500
        except Exception as e:
            log.exception("Erro ao listar logs")
            return {"msg": f"Erro ao buscar logs no Oracle: {e}"}, 500

class ExportLogs(Resource):
    def get(self):
        auth = require_login()
        if auth:
            return auth

        date_param = request.args.get("date") or request.args.get("datprocessamento") or request.args.get("data")
        if not date_param:
            return {"msg": "Informe a data (YYYY-MM-DD)."}, 400
        try:
            dt = normalize_bind_value("DATPROCESSAMENTO", date_param, {"data_type": "DATE"})
            d0 = dt.date()
            start = datetime(d0.year, d0.month, d0.day, 0, 0, 0)
            end = start + timedelta(days=1)
        except Exception:
            return {"msg": "Data Invalida."}, 400

                          
        try:
            req_timeout = request.args.get("timeout")
            timeout_ms = int(req_timeout) if req_timeout else max(app.config["ORACLE_CALL_TIMEOUT_MS"], 60000)
        except Exception:
            timeout_ms = max(app.config["ORACLE_CALL_TIMEOUT_MS"], 60000)

        try:
            with get_oracle_conn(call_timeout_ms=timeout_ms) as conn:
                cur = conn.cursor()
                index_hint = app.config["ORACLE_INDEX_HINT"]
                hint = f"/*+ {index_hint} */" if index_hint else ""
                select_list = ", ".join(f"u.{col}" for col in ListarLogs.LOG_COLUMNS)
                sql = f"""
                    SELECT * FROM (
                      SELECT {hint} {select_list}
                      FROM {app.config['ORACLE_TABLE_CLIENTES']} u
                      WHERE u.DATPROCESSAMENTO >= :p_start AND u.DATPROCESSAMENTO < :p_end
                      ORDER BY u.DATPROCESSAMENTO DESC, u.GUIA_COD_ID DESC
                    )
                    WHERE ROWNUM <= :p_limit
                """
                cur.prefetchrows = 1000
                cur.arraysize = 1000
                cur.execute(sql, {"p_start": start, "p_end": end, "p_limit": 100000})
                cols = [d[0] for d in cur.description]
                sio = io.StringIO()
                writer = csv.writer(sio, lineterminator='\n')
                writer.writerow(cols)
                for r in cur:
                                                                          
                    out_row = []
                    for v in r:
                        if isinstance(v, (datetime, date)):
                            out_row.append(v.isoformat())
                        elif isinstance(v, Decimal):
                            out_row.append(str(v))
                        else:
                            out_row.append("" if v is None else str(v))
                    writer.writerow(out_row)
                csv_data = sio.getvalue().encode('utf-8-sig')                  
                filename = f"logs_{start.date().isoformat()}.csv"
                headers = {
                    'Content-Type': 'text/csv; charset=utf-8',
                    'Content-Disposition': f'attachment; filename="{filename}"'
                }
                return Response(csv_data, headers=headers)
        except oracledb.Error as e:
            msg = str(e)
            if is_timeout_error(msg):
                return {"msg": "Tempo excedido ao consultar o Oracle."}, 504
            log.exception("Erro ao exportar logs")
            return {"msg": f"Erro ao exportar logs no Oracle: {msg}"}, 500
        except Exception as e:
            log.exception("Erro ao exportar logs")
            return {"msg": f"Erro ao exportar logs: {e}"}, 500

class ExcluirRegistro(Resource):
    def post(self):
        auth = require_login()
        if auth:
            return auth

        data = request.get_json(silent=True)
        if not data:
            data = {k: v for k, v in request.form.items()} if request.form else {}
        datprocessamento = data.get('DATPROCESSAMENTO') or data.get('date') or data.get('data')
        guia_cod = data.get('GUIA_COD') or data.get('guia_cod') or data.get('guia')
        if not datprocessamento or not guia_cod:
            return {"msg": "Informe DATPROCESSAMENTO e GUIA_COD."}, 400

        try:
            dt = normalize_bind_value("DATPROCESSAMENTO", datprocessamento, {"data_type": "DATE"})
            d0 = dt.date()
            start = datetime(d0.year, d0.month, d0.day, 0, 0, 0)
            end = start + timedelta(days=1)
        except Exception:
            return {"msg": "DATPROCESSAMENTO invÃ¡lido."}, 400

        try:
                                                                               
            try:
                req_timeout = request.args.get("timeout")
                timeout_ms = int(req_timeout) if req_timeout else app.config["ORACLE_CALL_TIMEOUT_MS"]
            except Exception:
                timeout_ms = app.config["ORACLE_CALL_TIMEOUT_MS"]

            with get_oracle_conn(call_timeout_ms=timeout_ms) as conn:
                cur = conn.cursor()
                sql = f"DELETE FROM {app.config['ORACLE_TABLE_CLIENTES']} WHERE DATPROCESSAMENTO >= :p_start AND DATPROCESSAMENTO < :p_end AND GUIA_COD = :p_guia"
                cur.execute(sql, {"p_start": start, "p_end": end, "p_guia": str(guia_cod).strip()})
                count = cur.rowcount or 0
                conn.commit()
                return {"msg": "Registro(s) excluido(s) com sucesso.", "deleted": count}, 200
        except oracledb.Error as e:
            msg = str(e)
            if is_timeout_error(msg):
                return {"msg": "Tempo excedido ao excluir no Oracle."}, 504
            log.exception("Erro ao excluir registro")
            return {"msg": f"Erro ao excluir no Oracle: {msg}"}, 500
        except Exception as e:
            log.exception("Erro ao excluir registro")
            return {"msg": f"Erro ao excluir registro: {e}"}, 500

api.add_resource(ListarLogs, '/api/logs')
api.add_resource(ExportLogs, '/api/logs/export')
api.add_resource(ExcluirRegistro, '/api/excluir-registro')

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
        },
        "table": app.config['ORACLE_TABLE_CLIENTES'],
        "datatypes": {}
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

                                         
        info["datatypes"]["DATPROCESSAMENTO"] = _col_dtype("DATPROCESSAMENTO")
        info["datatypes"]["SEQUENCIA"] = _col_dtype("SEQUENCIA")

        with get_oracle_conn(call_timeout_ms=3000) as conn:
            cur = conn.cursor()
            cur.execute("SELECT 1 FROM DUAL")
        info["oracle_ok"] = True
        return jsonify({"ok": True, "info": info})
    except Exception as e:
        return jsonify({"ok": False, "where": "oracle", "err": str(e), "info": info}), 500

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
