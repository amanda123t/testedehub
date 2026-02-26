"""
API FastAPI para o sistema de validação de documentos Sicredi.

Exposição do pipeline de validação via HTTP REST:
  - POST /validar         -> valida documentos de um processo
  - GET  /tipos-documento -> lista os tipos de documentos suportados
  - GET  /health          -> health check

Segurança implementada:
  - Autenticação por API Key (header X-API-Key)
  - Limite de tamanho de upload (MAX_UPLOAD_MB)
  - Sanitização de nomes de arquivo e campos de path
  - Tracebacks internos nunca expostos ao cliente
  - Swagger UI desabilitado em produção (API_ENV=production)
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from fastapi import FastAPI, File, Form, HTTPException, Security, UploadFile, status
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security.api_key import APIKeyHeader

load_dotenv()

log = logging.getLogger("sicredi_api")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# ---------------------------------------------------------------------------
# Configuração via variáveis de ambiente
# ---------------------------------------------------------------------------

API_KEY: str = os.getenv("API_KEY", "")
API_ENV: str = os.getenv("API_ENV", "development").lower()   # "production" desliga docs
MAX_UPLOAD_MB: int = int(os.getenv("MAX_UPLOAD_MB", "50"))   # limite por arquivo (MB)
MAX_UPLOAD_BYTES: int = MAX_UPLOAD_MB * 1024 * 1024

if not API_KEY:
    log.warning(
        "⚠️  API_KEY não definida no ambiente. "
        "Defina API_KEY=<segredo> no .env antes de colocar em produção."
    )

# ---------------------------------------------------------------------------
# App — Swagger desabilitado em produção
# ---------------------------------------------------------------------------

_docs_url    = None if API_ENV == "production" else "/docs"
_redoc_url   = None if API_ENV == "production" else "/redoc"
_openapi_url = None if API_ENV == "production" else "/openapi.json"

app = FastAPI(
    title="Sicredi – Validação de Documentos",
    description=(
        "API REST para validação automatizada de documentos do Sicredi. "
        "Recebe arquivos (PDF/imagem) e metadados do processo e retorna "
        "um relatório em PDF com o resultado da validação."
    ),
    version="1.1.0",
    contact={"name": "Sicredi RPA"},
    docs_url=_docs_url,
    redoc_url=_redoc_url,
    openapi_url=_openapi_url,
)

# ---------------------------------------------------------------------------
# Autenticação por API Key
# ---------------------------------------------------------------------------

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def verificar_api_key(key: Optional[str] = Security(_api_key_header)) -> str:
    """Valida o header X-API-Key. Lança 401 se inválida ou ausente."""
    if not API_KEY:
        # Sem API_KEY configurada → aceita em desenvolvimento, bloqueia em produção
        if API_ENV == "production":
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Servidor mal configurado: API_KEY não definida.",
            )
        return "dev-sem-chave"

    if not key or key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API Key inválida ou ausente. Envie o header X-API-Key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return key


# ---------------------------------------------------------------------------
# Tipos de documentos suportados
# ---------------------------------------------------------------------------

TIPOS_DOCUMENTOS: Dict[str, str] = {
    "ir_receipt":             "Recibo de IR",
    "irpf":                   "IRPF",
    "inss":                   "INSS",
    "address":                "Comprovante de Endereço",
    "prolabore":              "Pró-Labore",
    "income":                 "Renda Presumida",
    "paycheck":               "Holerite",
    "crlv":                   "CRLV",
    "self_declaration":       "Autodeclaração de Renda",
    "property_registration":  "Matrícula",
    "pricing":                "Precificação",
    "balance":                "Balanço Patrimonial",
    "dre":                    "DRE",
    "registration_pj":        "Cadastro PJ",
    "registration_pf":        "Cadastro PF",
    "invoice":                "Faturamento",
    "presumedbilling":        "Faturamento Presumido",
    "contract":               "Alteração Contratual",
    "nota_fiscal":            "Nota Fiscal",
    "cartao_cnpj":            "Cartão CNPJ",
    "simples":                "Simples Nacional",
    "pgdas":                  "PGDAS",
    "minute":                 "Ata de Eleição",
    "certificado_mei":        "Certificado MEI",
    "cnh":                    "CNH",
    "bank_statement":         "Extrato Bancário",
    "RG":                     "RG",
    "avaliacao":              "Laudo de Avaliação",
    "car":                    "CAR",
    "carteira_trabalho":      "Carteira de Trabalho",
    "casamento":              "Certidão de Casamento",
    "croqui":                 "Croqui",
    "fipe":                   "Tabela FIPE",
    "cpf_receita_federal":    "Comprovante Situação Cadastral – CPF",
    "consent":                "Anuência",
    "arrendamento":           "Contrato de Arrendamento",
    "comodato":               "Contrato de Comodato",
    "locacao":                "Contrato de Locação",
}

EXTENSOES_SUPORTADAS = {".pdf", ".png", ".jpg", ".jpeg", ".jfif", ".tif", ".tiff", ".bmp", ".webp"}

# ---------------------------------------------------------------------------
# Helpers de segurança
# ---------------------------------------------------------------------------

_SAFE_NAME = re.compile(r"[^\w\-.]")   # permite letras, dígitos, _ - .


def _sanitizar_nome(valor: str, max_len: int = 80) -> str:
    """
    Remove caracteres perigosos de um valor usado em paths de sistema de arquivos.
    Impede path traversal (../, ~/, etc.).
    """
    nome = _SAFE_NAME.sub("_", valor.strip())
    nome = nome.lstrip(".-")          # não pode começar com ponto ou hífen
    nome = nome[:max_len]             # limita o comprimento
    if not nome:
        nome = uuid.uuid4().hex
    return nome


def _salvar_arquivos(arquivos: List[UploadFile], destino: Path) -> List[str]:
    """
    Persiste os uploads em `destino` com validações de segurança:
    - Extensão permitida
    - Tamanho máximo (MAX_UPLOAD_BYTES)
    - Nome de arquivo sanitizado
    """
    salvos: List[str] = []
    for upload in arquivos:
        # 1. Extensão
        ext = Path(upload.filename or "").suffix.lower()
        if ext not in EXTENSOES_SUPORTADAS:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Extensão '{ext}' não suportada para '{upload.filename}'. "
                       f"Permitidas: {sorted(EXTENSOES_SUPORTADAS)}",
            )

        # 2. Nome sanitizado (evita path traversal via nome do arquivo)
        nome_base = _sanitizar_nome(Path(upload.filename or "sem_nome").stem)
        nome_final = f"{nome_base}{ext}"
        caminho = destino / nome_final

        # 3. Leitura com limite de tamanho
        conteudo = upload.file.read(MAX_UPLOAD_BYTES + 1)
        if len(conteudo) > MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Arquivo '{upload.filename}' excede o limite de {MAX_UPLOAD_MB} MB.",
            )

        caminho.write_bytes(conteudo)
        salvos.append(str(caminho))

    return salvos


def _carregar_pipeline():
    """Importa o pipeline sob demanda."""
    try:
        from app.modules.pipeline.by_process import by_process
        from app.modules.pipeline.errors import ColetorErrosNulo
        return by_process, ColetorErrosNulo
    except ImportError as exc:
        log.error("Pipeline indisponível: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Pipeline indisponível. Contate o administrador.",
        )


def _ler_resultado_json(pasta_output: Path, nome_processo: str) -> Optional[Dict[str, Any]]:
    candidatos = list(pasta_output.glob(f"pessoas_{nome_processo}.json"))
    if not candidatos:
        candidatos = list(pasta_output.glob("pessoas_*.json"))
    if candidatos:
        try:
            with candidatos[0].open(encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return None


def _encontrar_pdf(pasta_output: Path, nome_processo: str) -> Optional[Path]:
    candidatos = list(pasta_output.glob(f"{nome_processo}_resultado.pdf"))
    if not candidatos:
        candidatos = list(pasta_output.glob("*_resultado.pdf"))
    return candidatos[0] if candidatos else None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health", summary="Health check", tags=["Infra"])
def health():
    """Retorna `ok` quando o serviço está no ar. Não requer autenticação."""
    return {"status": "ok"}


@app.get(
    "/tipos-documento",
    summary="Tipos de documentos suportados",
    tags=["Documentos"],
    response_model=Dict[str, str],
)
def tipos_documento(_key: str = Security(verificar_api_key)):
    """Lista todos os tipos de documentos que o sistema consegue classificar e validar."""
    return TIPOS_DOCUMENTOS


@app.post(
    "/validar",
    summary="Validar documentos de um processo",
    tags=["Validação"],
    responses={
        200: {"description": "Relatório PDF de validação"},
        207: {"description": "Processado com avisos – JSON com detalhes"},
        401: {"description": "API Key inválida ou ausente"},
        413: {"description": "Arquivo excede o tamanho máximo permitido"},
        422: {"description": "Dados de entrada inválidos"},
        503: {"description": "Pipeline indisponível"},
    },
)
async def validar(
    arquivos: List[UploadFile] = File(...),
    informacoes_processo: str = Form(
        ...,
        description=(
            "JSON com os metadados do processo.\n"
            "Obrigatórios: `processo`, `colaborador`, `cooperativa`.\n"
            "Opcionais: `nome`, `cpf`, `cnpj`, `agencia`, `responsavel`."
        ),
    ),
    planilha_regras: Optional[UploadFile] = File(None),
    retornar_json: bool = Form(False),
    _key: str = Security(verificar_api_key),
):
    """
    Executa o pipeline completo de validação de documentos.

    Requer header **X-API-Key** com a chave configurada no servidor.
    Tamanho máximo por arquivo: configurado em `MAX_UPLOAD_MB` (padrão 50 MB).
    """

    # --- Parse e validação do JSON de entrada ---
    try:
        info: Dict[str, Any] = json.loads(informacoes_processo)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"'informacoes_processo' não é um JSON válido: {exc}",
        )

    campos_obrigatorios = ("processo", "colaborador", "cooperativa")
    faltando = [c for c in campos_obrigatorios if not str(info.get(c, "")).strip()]
    if faltando:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Campos obrigatórios ausentes: {faltando}",
        )

    if not arquivos:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="É necessário enviar ao menos um arquivo.",
        )

    # --- Sanitização dos campos usados em paths (fix path traversal) ---
    nome_processo: str = _sanitizar_nome(str(info["processo"]))
    cooperativa: str   = _sanitizar_nome(str(info["cooperativa"]))

    # Atualiza o dict com os valores sanitizados
    info["processo"]    = nome_processo
    info["cooperativa"] = cooperativa

    # --- Diretórios temporários ---
    base_temp = Path(tempfile.mkdtemp(prefix="sicredi_api_"))
    pasta_processo = base_temp / nome_processo
    pasta_processo.mkdir(parents=True, exist_ok=True)

    caminho_regras: Any = None
    if planilha_regras and planilha_regras.filename:
        ext_regras = Path(planilha_regras.filename).suffix.lower()
        if ext_regras not in {".xlsx", ".xls"}:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="planilha_regras deve ser .xlsx ou .xls.",
            )
        caminho_regras_path = base_temp / "REGRAS.xlsx"
        conteudo_regras = planilha_regras.file.read(MAX_UPLOAD_BYTES + 1)
        if len(conteudo_regras) > MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"planilha_regras excede {MAX_UPLOAD_MB} MB.",
            )
        caminho_regras_path.write_bytes(conteudo_regras)
        caminho_regras = str(caminho_regras_path)

    try:
        _salvar_arquivos(arquivos, pasta_processo)

        by_process, ColetorErrosNulo = _carregar_pipeline()
        coletor = ColetorErrosNulo()

        by_process(
            str(pasta_processo),
            info,
            caminho_planilha_regras=caminho_regras,
            coletor_erros=coletor,
        )

        pasta_output = (
            Path(__file__).resolve().parent
            / "output"
            / cooperativa
            / nome_processo
        )

        if retornar_json:
            resultado = _ler_resultado_json(pasta_output, nome_processo)
            if resultado is None:
                return JSONResponse(
                    status_code=status.HTTP_207_MULTI_STATUS,
                    content={
                        "aviso": "Pipeline executado mas nenhum JSON de resultado foi encontrado.",
                        "processo": nome_processo,
                    },
                )
            return JSONResponse(content=resultado)

        caminho_pdf = _encontrar_pdf(pasta_output, nome_processo)
        if caminho_pdf is None:
            return JSONResponse(
                status_code=status.HTTP_207_MULTI_STATUS,
                content={
                    "aviso": "Pipeline executado mas nenhum PDF foi gerado.",
                    "processo": nome_processo,
                },
            )

        return FileResponse(
            path=str(caminho_pdf),
            media_type="application/pdf",
            filename=f"{nome_processo}_resultado.pdf",
        )

    except HTTPException:
        raise
    except Exception as exc:
        # Loga internamente com traceback completo, mas NÃO expõe ao cliente
        log.exception("Erro interno ao processar processo '%s'", nome_processo)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno ao processar o processo. Contate o administrador.",
        )
    finally:
        shutil.rmtree(base_temp, ignore_errors=True)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "api:app",
        host=os.getenv("API_HOST", "0.0.0.0"),
        port=int(os.getenv("API_PORT", "8000")),
        reload=os.getenv("API_RELOAD", "false").lower() == "true",
        workers=int(os.getenv("API_WORKERS", "1")),
    )
