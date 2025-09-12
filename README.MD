# input para procurar beneficiario tabela uni0177_tbtipoguia_comp campo carterinha 
# 3 input para adicionar competencia, despesas_gerais, remocao , demais dados da tabela vai permanecer preenchido automaticamente conforme a ultima competencia



# Consulta e Cadastro de Clientes

Sistema web para consulta e cadastro de clientes/beneficiários, utilizando **Flask**, **SQLite** e **Bootstrap 5**. O projeto integra **validação frontend e backend**, garantindo que campos obrigatórios sejam preenchidos corretamente e fornecendo feedback visual aos usuários.

---

## Estrutura do Projeto

.
├── app_flask.py # Aplicação principal Flask
├── templates/
│ └── index.html # Frontend da aplicação (formulário e tabela)
├── static/
│ ├── css/ # Arquivos CSS customizados (opcional)
│ └── js/ # Arquivos JS customizados (opcional)
├── relacionamento_cliente.db # Banco de dados SQLite
├── README.md # Este arquivo

markdown
Copiar código

---

## Funcionalidades

1. **Consulta de clientes**
   - Pesquise clientes pelo número de matrícula.
   - Exibe uma tabela com os campos:
     - `CONTRATO`
     - `MATRICULA`
     - `COMPETENCIA_PAGAMENTO`
     - `BENEFICIARIO`
     - `VAL_FAT`
   - Caso não encontre registros, exibe a mensagem “Nenhum registro encontrado”.

2. **Cadastro de clientes/beneficiários**
   - Botão **Cadastrar** abre um modal para inserir a matrícula.
   - Ao informar a matrícula e continuar, outro modal abre com o formulário de cadastro.
   - Campos obrigatórios são destacados com `*` e possuem **feedback visual** caso não sejam preenchidos.
   - Campos como `DATPROCESSAMENTO` e `SEQUENCIA` são preenchidos automaticamente pelo sistema.
   - Integração com backend para validação final antes de inserir no banco.

---

## Campos do Formulário de Cadastro

### Campos obrigatórios (preenchimento obrigatório):

- `CONTRATO`
- `MATRICULA`
- `COMPETENCIA_PAGAMENTO`
- `ITEM_COD`
- `VALOR`
- `COMPETENCIA_PROCESSAMENTO`
- `DATA_EXECUCAO`
- `ITEM_DESCRI`
- `IDADE`
- `UNI_COD_RESPON`
- `COD_CNTRAT_CART`
- `COD`
- `COD_DEPNTE`
- `BENEFICIARIO`

### Campos automáticos (preenchidos pelo sistema):

- `DATPROCESSAMENTO` → data atual do cadastro.
- `SEQUENCIA` → sequência automática, calculada com base nos registros anteriores.

### Campos opcionais:

- Todos os outros campos que não são obrigatórios nem automáticos podem ser preenchidos, mas não são exigidos para o cadastro.

---

## Regras de Validação

- **Frontend**: campos obrigatórios possuem `invalid-feedback` do Bootstrap e são validados em tempo real.
- **Backend**: validação redundante para evitar inserção de dados inválidos via burla no frontend. Se algum campo obrigatório estiver vazio, o servidor retorna erro detalhado, destacando os campos inválidos no modal.

---

## Pré-requisitos

- Python 3.8 ou superior
- Flask
- SQLite (embutido no Python)
- Biblioteca jQuery (via CDN)
- Bootstrap 5 (via CDN)

---

## Instalação e execução

1. Clone o projeto:
```bash
git clone https://github.com/seu-usuario/consulta-clientes.git
cd consulta-clientes
Crie um ambiente virtual (opcional, mas recomendado):

bash
Copiar código
python -m venv venv
source venv/bin/activate  # Linux / Mac
venv\Scripts\activate     # Windows
Instale as dependências:

bash
Copiar código
pip install Flask
Crie o banco de dados SQLite:

bash
Copiar código
sqlite3 relacionamento_cliente.db
Crie a tabela uni0177_tbtipoguia_comp com os campos necessários (mesmos do formulário).

Execute a aplicação:

bash
Copiar código
python app_flask.py
Acesse no navegador:

cpp
Copiar código
http://127.0.0.1:5000/
Uso
Consulta: digite a matrícula no campo de busca e clique em Buscar.

Cadastrar: clique em Cadastrar, informe a matrícula e preencha os campos obrigatórios no formulário.

Validação:

Campos obrigatórios vazios são destacados em vermelho.

Mensagens do backend também são exibidas dinamicamente, sem recarregar a página.

Tecnologias Utilizadas
Python 3 + Flask → backend e API para cadastro/consulta.

SQLite → banco de dados leve e fácil de configurar.

Bootstrap 5 → interface responsiva e moderna.

jQuery → manipulação dinâmica do DOM e AJAX.

Observações
Campos automáticos (DATPROCESSAMENTO e SEQUENCIA) não podem ser editados pelo usuário.

O sistema garante que não seja possível burlar a validação apenas manipulando o frontend.

Para produção, recomenda-se trocar SQLite por um banco mais robusto (PostgreSQL, MySQL) e adicionar autenticação de usuários.

Autor
Kelven Silva