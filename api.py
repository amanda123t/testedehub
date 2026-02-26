"""
API FastAPI para o sistema de validação de documentos Sicredi.

Exposição do pipeline de validação via HTTP REST:
  - POST /validar         -> valida documentos de um processo
  - GET  /tipos-documento -> lista os tipos de documentos suportados
  - GET  /health          -> health check
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import traceback
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from fastapi import FastAPI, File, Form, HTTPException, UploadFile, status
from fastapi.responses import FileResponse, JSONResponse

load_dotenv()

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Sicredi – Validação de Documentos",
    description=(
        "API REST para validação automatizada de documentos do Sicredi. "
        "Recebe arquivos (PDF/imagem) e metadados do processo e retorna "
        "um relatório em PDF com o resultado da validação."
    ),
    version="1.0.0",
    contact={"name": "Sicredi RPA"},
)

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
# Helpers
# ---------------------------------------------------------------------------

def _salvar_arquivos(arquivos: List[UploadFile], destino: Path) -> List[str]:
    """Persiste os uploads em `destino` e retorna a lista de caminhos."""
    salvos: List[str] = []
    for upload in arquivos:
        ext = Path(upload.filename or "").suffix.lower()
        if ext not in EXTENSOES_SUPORTADAS:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Extensão '{ext}' não suportada para '{upload.filename}'. "
                       f"Use: {sorted(EXTENSOES_SUPORTADAS)}",
            )
        caminho = destino / (upload.filename or f"doc{uuid.uuid4().hex}{ext}")
        with caminho.open("wb") as f:
            shutil.copyfileobj(upload.file, f)
        salvos.append(str(caminho))
    return salvos


def _carregar_pipeline():
    """Importa o pipeline sob demanda para não travar o startup se faltar .env."""
    try:
        from app.modules.pipeline.by_process import by_process
        from app.modules.pipeline.errors import ColetorErrosNulo
        return by_process, ColetorErrosNulo
    except ImportError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Pipeline indisponível – verifique o ambiente: {exc}",
        )


def _ler_resultado_json(pasta_output: Path, nome_processo: str) -> Optional[Dict[str, Any]]:
    """Lê o JSON de pessoas gerado pelo pipeline, se existir."""
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
    """Localiza o PDF de resultado gerado pelo pipeline."""
    candidatos = list(pasta_output.glob(f"{nome_processo}_resultado.pdf"))
    if not candidatos:
        candidatos = list(pasta_output.glob("*_resultado.pdf"))
    return candidatos[0] if candidatos else None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health", summary="Health check", tags=["Infra"])
def health():
    """Retorna `ok` quando o serviço está no ar."""
    return {"status": "ok"}


@app.get(
    "/tipos-documento",
    summary="Tipos de documentos suportados",
    tags=["Documentos"],
    response_model=Dict[str, str],
)
def tipos_documento():
    """Lista todos os tipos de documentos que o sistema consegue classificar e validar."""
    return TIPOS_DOCUMENTOS


@app.post(
    "/validar",
    summary="Validar documentos de um processo",
    tags=["Validação"],
    responses={
        200: {"description": "Relatório PDF de validação"},
        207: {"description": "Processado com avisos – JSON com detalhes"},
        422: {"description": "Dados de entrada inválidos"},
        503: {"description": "Pipeline indisponível"},
    },
)
async def validar(
    arquivos: List[UploadFile] = File(
        ...,
        description=(
            "Arquivos do processo (PDF, PNG, JPG, TIFF, BMP, WEBP). "
            "Envie quantos forem necessários."
        ),
    ),
    informacoes_processo: str = Form(
        ...,
        description=(
            "JSON com os metadados do processo. Campos obrigatórios:\n"
            "- `processo` (str): número/identificador do processo\n"
            "- `colaborador` (str): nome do colaborador responsável\n"
            "- `cooperativa` (str): código ou nome da cooperativa\n\n"
            "Campos opcionais úteis: `nome`, `cpf`, `cnpj`, `agencia`, `responsavel`."
        ),
    ),
    planilha_regras: Optional[UploadFile] = File(
        None,
        description="Planilha REGRAS.xlsx com as regras de validação (opcional).",
    ),
    retornar_json: bool = Form(
        False,
        description="Se `true`, retorna JSON com o resultado em vez do PDF.",
    ),
):
    """
    Executa o pipeline completo de validação de documentos.

    **Fluxo interno:**
    1. Salva os arquivos recebidos em pasta temporária
    2. Extrai texto via OCR / leitura nativa de PDF
    3. Classifica cada documento (tipo: holerite, IRPF, etc.)
    4. Extrai dados estruturados via LLM
    5. Valida contra regras de negócio
    6. Gera relatório PDF consolidado

    **Retorno padrão:** arquivo PDF com o resultado.
    **Com `retornar_json=true`:** objeto JSON com validações por pessoa.
    """

    # --- Parsear e validar informacoes_processo ---
    try:
        info: Dict[str, Any] = json.loads(informacoes_processo)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"'informacoes_processo' não é um JSON válido: {exc}",
        )

    campos_obrigatorios = ("processo", "colaborador", "cooperativa")
    faltando = [c for c in campos_obrigatorios if not info.get(c)]
    if faltando:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Campos obrigatórios ausentes em 'informacoes_processo': {faltando}",
        )

    nome_processo: str = str(info["processo"]).strip()
    cooperativa: str = str(info["cooperativa"]).strip()

    if not arquivos:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="É necessário enviar ao menos um arquivo.",
        )

    # --- Diretórios temporários ---
    base_temp = Path(tempfile.mkdtemp(prefix="sicredi_api_"))
    pasta_processo = base_temp / nome_processo
    pasta_processo.mkdir(parents=True, exist_ok=True)

    # Planilha de regras
    caminho_regras: Any = None
    if planilha_regras and planilha_regras.filename:
        caminho_regras_path = base_temp / "REGRAS.xlsx"
        with caminho_regras_path.open("wb") as f:
            shutil.copyfileobj(planilha_regras.file, f)
        # O pipeline aceita tanto caminho (str/Path) quanto workbook já carregado.
        # Passamos o caminho como string – o pipeline internamente pode ler.
        caminho_regras = str(caminho_regras_path)

    try:
        # --- Salvar arquivos do processo ---
        _salvar_arquivos(arquivos, pasta_processo)

        # --- Carregar e executar pipeline ---
        by_process, ColetorErrosNulo = _carregar_pipeline()
        coletor = ColetorErrosNulo()

        by_process(
            str(pasta_processo),
            info,
            caminho_planilha_regras=caminho_regras,
            coletor_erros=coletor,
        )

        # --- Localizar saídas ---
        # O pipeline grava em: <projeto>/output/<cooperativa>/<processo>/
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

        # Retorno padrão: PDF
        caminho_pdf = _encontrar_pdf(pasta_output, nome_processo)
        if caminho_pdf is None:
            return JSONResponse(
                status_code=status.HTTP_207_MULTI_STATUS,
                content={
                    "aviso": "Pipeline executado mas nenhum PDF de resultado foi gerado.",
                    "processo": nome_processo,
                    "cooperativa": cooperativa,
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
        tb = traceback.format_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"erro": str(exc), "traceback": tb},
        )
    finally:
        # Remove pasta temporária de entrada (os outputs ficam em /output/)
        shutil.rmtree(base_temp, ignore_errors=True)


# ---------------------------------------------------------------------------
# Entrypoint direto
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
