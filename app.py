from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_restful import Api, Resource
from contextlib import contextmanager
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from collections import OrderedDict
from dotenv import load_dotenv
import logging
import os
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
# CONFIG (mínima)
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

app = Flask(__name__)
app.config.from_object(Config)
api = Api(app)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

# ====================================================================
# ORACLE: THICK + DSN + contextmanager
# ====================================================================
if app.config["ORACLE_THICK_LIB_DIR"]:
    try:
        oracledb.init_oracle_client(lib_dir=app.config["ORACLE_THICK_LIB_DIR"])
        log.info("Oracle client THICK habilitado.")
    except Exception as e:
        log.warning(f"Falha ao iniciar Oracle THICK: {e}. Tentará modo THIN.")

ORACLE_DSN = oracledb.makedsn(
    host=app.config["ORACLE_HOST"],
    port=app.config["ORACLE_PORT"],
    service_name=app.config["ORACLE_SERVICE"],
)

@contextmanager
def get_oracle_conn():
    conn = None
    try:
        conn = oracledb.connect(
            user=app.config["ORACLE_USER"],
            password=app.config["ORACLE_PASSWORD"],
            dsn=ORACLE_DSN,
        )
        yield conn
    finally:
        if conn:
            try: conn.close()
            except: pass

# cache de colunas
_ORACLE_TABLE_COLUMNS = []

def get_oracle_table_columns():
    global _ORACLE_TABLE_COLUMNS
    if _ORACLE_TABLE_COLUMNS:
        return _ORACLE_TABLE_COLUMNS
    try:
        with get_oracle_conn() as conn:
            cur = conn.cursor()
            cur.execute(f"SELECT * FROM {app.config['ORACLE_TABLE_CLIENTES']} WHERE ROWNUM = 1")
            _ORACLE_TABLE_COLUMNS = [c[0] for c in (cur.description or [])]
            if not _ORACLE_TABLE_COLUMNS:
                log.warning("Nenhuma coluna encontrada (tabela vazia?).")
    except Exception as e:
        log.error(f"Erro ao buscar colunas Oracle: {e}")
        _ORACLE_TABLE_COLUMNS = []
    return _ORACLE_TABLE_COLUMNS


_ORACLE_TABLE_METADATA = OrderedDict()


def get_oracle_table_metadata():
    global _ORACLE_TABLE_METADATA
    if _ORACLE_TABLE_METADATA:
        return _ORACLE_TABLE_METADATA

    owner, table = _split_owner_table(app.config['ORACLE_TABLE_CLIENTES'])
    meta = OrderedDict()
    try:
        with get_oracle_conn() as conn:
            cur = conn.cursor()
            if owner:
                cur.execute(
                    """
                        SELECT column_name, data_type, data_precision, data_scale, nullable, column_id
                        FROM all_tab_columns
                        WHERE owner = :owner AND table_name = :table
                        ORDER BY column_id
                    """,
                    {"owner": owner, "table": table},
                )
            else:
                cur.execute(
                    """
                        SELECT column_name, data_type, data_precision, data_scale, nullable, column_id
                        FROM user_tab_columns
                        WHERE table_name = :table
                        ORDER BY column_id
                    """,
                    {"table": table},
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

    if dtype == "DATE":
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
# ORACLE helpers
# ====================================================================
def _split_owner_table(ref: str):
    """Retorna (owner, table) a partir de "OWNER.TABLE" ou (None, ref) se sem owner."""
    if not ref:
        return None, None
    parts = ref.split('.')
    if len(parts) == 2:
        return parts[0].upper(), parts[1].upper()
    return None, ref.upper()

def get_table_rowcount_estimate(conn, table_ref: str):
    """Tenta obter contagem estimada via estatística (ALL_TABLES/USER_TABLES). Retorna int ou None."""
    owner, table = _split_owner_table(table_ref)
    cur = conn.cursor()
    try:
        if owner:
            cur.execute("""
                SELECT num_rows FROM all_tables
                WHERE owner = :1 AND table_name = :2
            """, (owner, table))
        else:
            cur.execute("""
                SELECT num_rows FROM user_tables
                WHERE table_name = :1
            """, (table,))
        row = cur.fetchone()
        if row and row[0] is not None:
            return int(row[0])
    except Exception as _:
        pass
    return None

# ====================================================================
# SQLITE
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
        # evita NaN/Infinity no JSON
        try: return float(value)
        except: return None
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value

def row_to_dict(columns, row):
    return {col: sanitize(val) for col, val in zip(columns, row)}

def normalize_remocao(expr_col="TIPO_ATENDIMENTO"):
    return f"REPLACE(REPLACE(REPLACE(UPPER({expr_col}),'Ç','C'),'Ã','A'),'Õ','O')"

def require_login():
    if 'user_id' not in session:
        return {"msg": "Usuário não autenticado."}, 401

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
                cur.execute(
                    "INSERT INTO usuarios (nome, login, email, senha, funcao) VALUES (?, ?, ?, ?, ?)",
                    (data['nome'], data['login'], data['email'], data['senha'], data['funcao'])
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
                user = conn.execute("SELECT id, nome, senha FROM usuarios WHERE login = ?", (data["login"],)).fetchone()
                if not user or user["senha"] != data["senha"]:
                    return {"msg": "Usuário ou senha inválidos."}, 401
                session["user_id"] = user["id"]
                session["user_name"] = user["nome"]
                return {"msg": "Login realizado com sucesso."}, 200
        except Exception as e:
            log.exception("Erro no login")
            return {"msg": f"Erro interno no login: {e}"}, 500

class ListarClientes(Resource):
    def get(self):
        # Versão simples: sem autenticação e sem paginação custosa
        try:
            limit_req = int(request.args.get("limit", 10))
            limit = min(app.config["MAX_PAGE_SIZE"], max(1, limit_req))
        except ValueError:
            return {"msg": "Parâmetro 'limit' inválido."}, 400

        try:
            with get_oracle_conn() as conn:
                cur = conn.cursor()

                # Simples: retorna os primeiros N registros sem COUNT(*)
                sql = f"""
                    SELECT CONTRATO, MATRICULA, COMPETENCIA_PAGAMENTO, BENEFICIARIO, VALOR
                    FROM (
                        SELECT CONTRATO, MATRICULA, COMPETENCIA_PAGAMENTO, BENEFICIARIO, VALOR
                        FROM {app.config['ORACLE_TABLE_CLIENTES']}
                    )
                    WHERE ROWNUM <= :1
                """
                cur.execute(sql, (limit,))

                cols = [d[0] for d in cur.description]
                rows = [row_to_dict(cols, r) for r in cur.fetchall()]

                log.info(f"/api/clientes -> limit={limit} retornados={len(rows)}")

                # Mantém chaves esperadas pelo front; 'total' zerado esconde paginação
                return {"clientes": rows, "page": 1, "limit": limit, "total": 0}, 200

        except Exception as e:
            log.exception("Erro ao listar clientes")
            return {"msg": f"Erro ao buscar clientes no Oracle: {e}"}, 500

class BuscarUltimoCadastro(Resource):
    def get(self):
        # Versão simples: não exige autenticação

        matricula = request.args.get("matricula")
        if not matricula:
            return {"msg": "Matrícula não fornecida."}, 400

        try:
            with get_oracle_conn() as conn:
                cur = conn.cursor()

                # Query: busca o último cadastro da matrícula priorizando casos de remoção e calcula a próxima sequência global

                sql = f"""
                    WITH CANDIDATOS AS (
                        SELECT u.*,
                               ROW_NUMBER() OVER (
                                   ORDER BY
                                       CASE
                                           WHEN TRANSLATE(UPPER(TRIM(u.TIPO_ATENDIMENTO)), UNISTR('\\00C7\\00C3\\00C2\\00C1\\00C0\\00D5'), 'CAAAAO') = 'REMOCAO' THEN 0
                                           ELSE 1
                                       END,
                                       u.COMPETENCIA_PROCESSAMENTO DESC NULLS LAST,
                                       u.SEQUENCIA DESC NULLS LAST
                               ) AS RN
                        FROM {app.config['ORACLE_TABLE_CLIENTES']} u
                        WHERE u.MATRICULA = :matricula
                    ),
                    MAX_GERAL AS (
                        SELECT MAX(SEQUENCIA) AS SEQUENCIA_GERAL FROM {app.config['ORACLE_TABLE_CLIENTES']}
                    )
                    SELECT
                        NVL(MAX_GERAL.SEQUENCIA_GERAL, 0) AS SEQUENCIA_GERAL,
                        NVL(MAX_GERAL.SEQUENCIA_GERAL, 0) + 1 AS PROXIMA_SEQUENCIA,
                        ULTIMO.*
                    FROM MAX_GERAL
                    LEFT JOIN (
                        SELECT * FROM CANDIDATOS WHERE RN = 1
                    ) ULTIMO ON 1 = 1
                """
                cur.execute(sql, {"matricula": matricula})
                row = cur.fetchone()

                data = {"MATRICULA": matricula}
                tem_cadastro = False
                if row:
                    cols = [d[0] for d in cur.description]
                    row_dict = row_to_dict(cols, row)
                    data.update(row_dict)
                    tem_cadastro = any(
                        row_dict.get(col) is not None
                        for col in row_dict
                        if col not in {"SEQUENCIA_GERAL", "PROXIMA_SEQUENCIA"}
                    )

                msg = "Dados encontrados." if tem_cadastro else "Nenhum cadastro anterior encontrado para esta matrícula."
                return {"msg": msg, "data": data}, 200

        except Exception as e:
            log.exception("Erro no último cadastro")
            return {"msg": f"Erro ao buscar cadastro: {e}"}, 500

class CadastrarCliente(Resource):
    def post(self):
        auth = require_login()
        if auth: return auth

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
                column = key.upper()
                if column in metadata:
                    incoming[column] = value

            if not incoming:
                return {"msg": "Nenhuma coluna valida para insercao."}, 400

            if "DATPROCESSAMENTO" not in incoming:
                incoming["DATPROCESSAMENTO"] = datetime.now()
            if "SEQUENCIA" in incoming and "SEQ" not in incoming:
                incoming["SEQ"] = incoming["SEQUENCIA"]

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

            with get_oracle_conn() as conn:
                cur = conn.cursor()
                cur.execute(sql, normalized)
                conn.commit()

            return {"msg": "Cliente cadastrado com sucesso!"}, 201

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
    try:
        with get_sqlite_db() as c: c.execute("SELECT 1")
        with get_oracle_conn() as conn:
            cur = conn.cursor(); cur.execute("SELECT 1 FROM DUAL")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "err": str(e)}), 500

if __name__ == "__main__":
    # pré-carrega colunas (falha cedo se service/credencial estiver errado)
    get_oracle_table_columns()
    app.run(debug=True, host="0.0.0.0")







