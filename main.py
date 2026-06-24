import base64
import hmac
import io
import os

import pdfplumber
import anthropic
from dotenv import load_dotenv
from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.responses import Response

load_dotenv()

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
if not ANTHROPIC_API_KEY:
    raise RuntimeError("ANTHROPIC_API_KEY 환경변수가 설정되지 않았습니다.")

SITE_PASSWORD = os.environ.get("SITE_PASSWORD")
if not SITE_PASSWORD:
    raise RuntimeError("SITE_PASSWORD 환경변수가 설정되지 않았습니다.")

client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

MAX_FILE_SIZE = 10 * 1024 * 1024
MAX_CHARS = 30000

app = FastAPI(title="계약서 리스크 체커")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def require_password(request: Request, call_next):
    auth_header = request.headers.get("authorization", "")
    password = ""
    if auth_header.startswith("Basic "):
        try:
            decoded = base64.b64decode(auth_header[6:]).decode()
            password = decoded.partition(":")[2]
        except Exception:
            password = ""
    if not hmac.compare_digest(password, SITE_PASSWORD):
        return Response(status_code=401, headers={"WWW-Authenticate": "Basic"})
    return await call_next(request)

RISK_TOOL = {
    "name": "report_contract_risks",
    "description": "계약서 분석 결과를 보고한다",
    "input_schema": {
        "type": "object",
        "properties": {
            "overall_risk_score": {
                "type": "integer",
                "description": "0~100 사이 전체 위험도 점수, 높을수록 위험",
            },
            "summary": {
                "type": "string",
                "description": "계약서 전반에 대한 2~3문장 요약",
            },
            "clauses": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "quote": {"type": "string", "description": "원문에서 발췌한 문제 조항"},
                        "risk_level": {"type": "string", "enum": ["high", "medium", "low"]},
                        "reason": {"type": "string", "description": "왜 위험한지 설명"},
                        "suggestion": {
                            "type": "string",
                            "description": "상대방에게 요청할 수 있는 수정 문구 제안",
                        },
                    },
                    "required": ["quote", "risk_level", "reason", "suggestion"],
                },
            },
        },
        "required": ["overall_risk_score", "summary", "clauses"],
    },
}

SYSTEM_PROMPT = (
    "당신은 프리랜서와 소상공인이 계약서를 검토할 때 위험 조항을 찾아주는 보조 도구입니다. "
    "이것은 법률 자문이 아니며 정보 제공 목적의 1차 검토임을 항상 전제합니다. "
    "한국 계약 실무 기준으로 다음을 중점적으로 찾으세요: "
    "과도하거나 무제한적인 손해배상 조항, 일방적 계약 해지권, 불명확하거나 지연된 대금 지급 조건, "
    "과도한 위약금, 과도한 비밀유지/경업금지 조항, 불공정한 지식재산권 귀속 조항, 모호한 업무 범위. "
    "발견한 조항은 원문을 그대로 인용하고, 위험 수준과 이유, 수정 제안을 함께 제시하세요."
)


def extract_text(pdf_bytes: bytes) -> str:
    text_parts = []
    with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
        for page in pdf.pages:
            page_text = page.extract_text()
            if page_text:
                text_parts.append(page_text)
    return "\n".join(text_parts)


@app.post("/api/analyze")
async def analyze_contract(file: UploadFile = File(...)):
    if file.content_type != "application/pdf":
        raise HTTPException(400, "PDF 파일만 업로드할 수 있습니다.")

    contents = await file.read()
    if len(contents) > MAX_FILE_SIZE:
        raise HTTPException(400, "파일 크기는 10MB를 초과할 수 없습니다.")

    text = extract_text(contents)
    if not text.strip():
        raise HTTPException(422, "PDF에서 텍스트를 추출할 수 없습니다. 스캔본인 경우 OCR이 필요합니다.")

    text = text[:MAX_CHARS]

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=4096,
        system=SYSTEM_PROMPT,
        tools=[RISK_TOOL],
        tool_choice={"type": "tool", "name": "report_contract_risks"},
        messages=[{"role": "user", "content": f"다음 계약서를 분석해주세요:\n\n{text}"}],
    )

    tool_use = next((block for block in response.content if block.type == "tool_use"), None)
    if tool_use is None:
        raise HTTPException(502, "분석 결과를 생성하지 못했습니다.")

    return tool_use.input


app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
