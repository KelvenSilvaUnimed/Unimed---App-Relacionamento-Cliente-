import pandas as pd
import sqlite3
import os

# --- Configurações ---
ARQUIVO_EXCEL = 'uni0177_tbtipoguia_comp.xlsx'
NOME_TABELA = 'uni0177_tbtipoguia_comp'
DB_NAME = 'relacionamento_cliente.db'

COLUNAS_TABELA = [
    "DATPROCESSAMENTO", "CONTRATO", "MATRICULA",
    "COMPETENCIA_PAGAMENTO", "GUIA_COD_ID", "COD_ID_GUIA_GERAL", "TP_GUIA",
    "ITEM_COD", "TIP_GUIA", "VALOR", "ORIGEM_REDE", "DEMONSTRATIVO_FATURA",
    "COMPETENCIA_PROCESSAMENTO", "GUCID_COD_CID", "TP_ITEM", "SEQ", "DATA_EXECUCAO",
    "QTDE", "LOCALIDADE", "UNIMED_EXEC", "INDICACAO_CLINICA", "GRUPO_FREQUENCIA",
    "PREST_PAG", "TIP_FOR", "FORNECEDOR", "ITEM_DESCRI", "NM_SOLIC", "NC",
    "SEQUENCIA", "TIPO_LANCAMENTO", "CAPITULO", "GRUPO", "SUBGRUPO",
    "CARATER_ATENDIMENTO", "IDADE", "TIPO_ATENDIMENTO", "TIPO_ACOMODACAO",
    "PARTICIPACAO", "UNIMED", "GUIA_COD", "GUIA_COD_PREST", "NOME_PREST",
    "CBO_EXEC_NRO", "CBO_SOLIC_NRO", "VAL_FAT", "FAT_NRO", "COD_PREST_PAGTO",
    "UNI_COD_RESPON", "COD_CNTRAT_CART", "COD", "COD_DEPNTE", "BENEFICIARIO",
    "GUITE_NRO_SENHA_SOLIT", "PRESTADOR_EXECUTANTE_ITEM", "PARAMETRO_INT",
    "PARAMETRO_LOC", "CPFCNPJ_EXEC", "CPFCNPJ_SOL", "OBSERVACO", "STATUS"
]

def criar_tabela():
    """Cria a tabela no banco de dados se ela não existir."""
    conn = None
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        colunas_sql = ", ".join([f"{coluna} TEXT" for coluna in COLUNAS_TABELA])
        
        query_criacao = f"""
            CREATE TABLE IF NOT EXISTS {NOME_TABELA} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                {colunas_sql}
            );
        """
        cursor.execute(query_criacao)
        conn.commit()
        print("Tabela verificada/criada com sucesso.")
    except sqlite3.Error as e:
        print(f"Erro ao criar a tabela: {e}")
    finally:
        if conn:
            conn.close()

def converter_datas_para_str(df):
    """Converte todas as colunas de data para string (para SQLite)."""
    for coluna in df.columns:
        if pd.api.types.is_datetime64_any_dtype(df[coluna]):
            df[coluna] = df[coluna].astype(str)
    return df

def inserir_dados_do_excel():
    """Lê um arquivo .xlsx e insere os dados em uma tabela SQLite."""
    if not os.path.exists(ARQUIVO_EXCEL):
        print(f"Erro: O arquivo '{ARQUIVO_EXCEL}' não foi encontrado.")
        return

    criar_tabela()

    try:
        print("Lendo o arquivo Excel...")
        df = pd.read_excel(ARQUIVO_EXCEL, header=0, usecols=COLUNAS_TABELA)
        df.columns = df.columns.str.strip()
        
        # Converte colunas de datas para string
        df = converter_datas_para_str(df)

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        colunas = ', '.join(COLUNAS_TABELA)
        placeholders = ', '.join(['?'] * len(COLUNAS_TABELA))
        sql = f"INSERT INTO {NOME_TABELA} ({colunas}) VALUES ({placeholders})"

        print(f"Iniciando a inserção de {len(df)} registros...")
        cursor.executemany(sql, df.values.tolist())
        conn.commit()
        print("Inserção concluída com sucesso!")

    except Exception as e:
        print(f"Ocorreu um erro: {e}")
        if 'conn' in locals() and conn:
            conn.rollback()
    finally:
        if 'conn' in locals() and conn:
            conn.close()

if __name__ == "__main__":
    inserir_dados_do_excel()
