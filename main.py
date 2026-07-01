import base64
import hashlib
import hmac
import io
import os
import re
import secrets
import sqlite3
import time

import pdfplumber
import anthropic
from dotenv import load_dotenv
from fastapi import Cookie, Depends, FastAPI, File, Header, HTTPException, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from PIL import Image

load_dotenv()

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
if not ANTHROPIC_API_KEY:
    raise RuntimeError("ANTHROPIC_API_KEY 환경변수가 설정되지 않았습니다.")

client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

MAX_FILE_SIZE = 25 * 1024 * 1024
MAX_CHARS = 30000
MAX_IMAGE_DIMENSION = 1568
MAX_IMAGE_BYTES = 4 * 1024 * 1024
IMAGE_CONTENT_TYPES = {"image/jpeg", "image/png", "image/webp"}

DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")
SESSION_COOKIE = "session"
SESSION_TTL_SECONDS = 30 * 24 * 3600
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PBKDF2_ITERATIONS = 200_000


def _init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        """
    )
    conn.commit()
    conn.close()


def get_db():
    return sqlite3.connect(DB_PATH)


def hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS).hex()


def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + SESSION_TTL_SECONDS
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
            (token, user_id, expires_at),
        )
        conn.commit()
    finally:
        conn.close()
    return token


def get_current_user(session: str | None = Cookie(default=None)) -> dict:
    if not session:
        raise HTTPException(401, "로그인이 필요합니다.")
    now = int(time.time())
    conn = get_db()
    try:
        row = conn.execute(
            """
            SELECT u.id, u.email FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token = ? AND s.expires_at > ?
            """,
            (session, now),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        raise HTTPException(401, "로그인이 필요합니다.")
    return {"id": row[0], "email": row[1]}


class SignupRequest(BaseModel):
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


_init_db()

app = FastAPI(title="계약서 리스크 체커")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/api/signup")
async def signup(body: SignupRequest):
    email = body.email.strip().lower()
    if not EMAIL_RE.match(email):
        raise HTTPException(400, "올바른 이메일 형식이 아닙니다.")
    if len(body.password) < 8:
        raise HTTPException(400, "비밀번호는 8자 이상이어야 합니다.")

    salt = secrets.token_bytes(16)
    password_hash = hash_password(body.password, salt)

    conn = get_db()
    try:
        cursor = conn.execute(
            "INSERT INTO users (email, password_hash, salt, created_at) VALUES (?, ?, ?, ?)",
            (email, password_hash, salt.hex(), time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
        )
        conn.commit()
        user_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        raise HTTPException(409, "이미 가입된 이메일입니다.")
    finally:
        conn.close()

    response = Response(status_code=204)
    response.set_cookie(
        SESSION_COOKIE,
        create_session(user_id),
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        samesite="lax",
        secure=os.environ.get("HTTPS") == "true",
    )
    return response


@app.post("/api/login")
async def login(body: LoginRequest):
    email = body.email.strip().lower()
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT id, password_hash, salt FROM users WHERE email = ?", (email,)
        ).fetchone()
    finally:
        conn.close()

    _dummy_salt = bytes(16)
    _dummy_hash = "0" * 64
    if row is None:
        hmac.compare_digest(hash_password(body.password, _dummy_salt), _dummy_hash)
        raise HTTPException(401, "이메일 또는 비밀번호가 올바르지 않습니다.")

    user_id, password_hash, salt_hex = row
    if not hmac.compare_digest(hash_password(body.password, bytes.fromhex(salt_hex)), password_hash):
        raise HTTPException(401, "이메일 또는 비밀번호가 올바르지 않습니다.")

    response = Response(status_code=204)
    response.set_cookie(
        SESSION_COOKIE,
        create_session(user_id),
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        samesite="lax",
        secure=os.environ.get("HTTPS") == "true",
    )
    return response


@app.post("/api/logout")
async def logout(session: str | None = Cookie(default=None)):
    if session:
        conn = get_db()
        try:
            conn.execute("DELETE FROM sessions WHERE token = ?", (session,))
            conn.commit()
        finally:
            conn.close()
    response = Response(status_code=204)
    response.delete_cookie(SESSION_COOKIE)
    return response


@app.get("/api/me")
async def me(user: dict = Depends(get_current_user)):
    return {"email": user["email"]}


ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN")


@app.get("/api/admin/stats")
async def admin_stats(x_admin_token: str | None = Header(default=None)):
    if not ADMIN_TOKEN or not x_admin_token or not hmac.compare_digest(x_admin_token, ADMIN_TOKEN):
        raise HTTPException(404)
    conn = get_db()
    try:
        user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    finally:
        conn.close()
    return {"user_count": user_count}

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


def prepare_image(image_bytes: bytes) -> str:
    image = Image.open(io.BytesIO(image_bytes))
    image = image.convert("RGB")

    if max(image.size) > MAX_IMAGE_DIMENSION:
        image.thumbnail((MAX_IMAGE_DIMENSION, MAX_IMAGE_DIMENSION), Image.LANCZOS)

    quality = 85
    while True:
        buffer = io.BytesIO()
        image.save(buffer, format="JPEG", quality=quality)
        if buffer.tell() <= MAX_IMAGE_BYTES or quality <= 40:
            break
        quality -= 15

    return base64.b64encode(buffer.getvalue()).decode()


@app.post("/api/analyze")
async def analyze_contract(file: UploadFile = File(...), user: dict = Depends(get_current_user)):
    is_pdf = file.content_type == "application/pdf"
    is_image = file.content_type in IMAGE_CONTENT_TYPES
    if not is_pdf and not is_image:
        raise HTTPException(400, "PDF 또는 이미지(JPEG/PNG/WEBP) 파일만 업로드할 수 있습니다.")

    contents = await file.read()
    if len(contents) > MAX_FILE_SIZE:
        raise HTTPException(400, "파일 크기는 25MB를 초과할 수 없습니다.")

    if is_pdf:
        text = extract_text(contents)
        if not text.strip():
            raise HTTPException(422, "PDF에서 텍스트를 추출할 수 없습니다. 스캔본인 경우 이미지 파일로 업로드해보세요.")
        text = text[:MAX_CHARS]
        user_content = f"다음 계약서를 분석해주세요:\n\n{text}"
    else:
        try:
            image_b64 = prepare_image(contents)
        except Exception:
            raise HTTPException(422, "이미지를 읽을 수 없습니다. 다른 파일로 시도해주세요.")
        user_content = [
            {
                "type": "image",
                "source": {"type": "base64", "media_type": "image/jpeg", "data": image_b64},
            },
            {"type": "text", "text": "이 사진에 담긴 계약서를 분석해주세요."},
        ]

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=4096,
        system=SYSTEM_PROMPT,
        tools=[RISK_TOOL],
        tool_choice={"type": "tool", "name": "report_contract_risks"},
        messages=[{"role": "user", "content": user_content}],
    )

    tool_use = next((block for block in response.content if block.type == "tool_use"), None)
    if tool_use is None:
        raise HTTPException(502, "분석 결과를 생성하지 못했습니다.")

    return tool_use.input


app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
