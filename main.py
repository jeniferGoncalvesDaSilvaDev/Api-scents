from fastapi import FastAPI, UploadFile, File, Depends, HTTPException, Path, Request
from sqlalchemy.orm import Session
from database import get_db, engine
import models
import datetime

# Criar tabelas
models.Base.metadata.create_all(bind=engine)

from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator, EmailStr
from passlib.context import CryptContext

app = FastAPI(
    title="Scents API",
    description="API para envio e processamento de anúncios com Scents",
    version="1.1.0",
    openapi_tags=[
        {"name": "Autenticação", "description": "Endpoints para gerenciamento de usuários e autenticação"},
        {"name": "Anúncios", "description": "Endpoints para upload e processamento de anúncios"},
        {"name": "Visualização", "description": "Endpoints para visualização de anúncios"},
        {"name": "Estatísticas", "description": "Endpoints para visualização de estatísticas de anúncios"},
        {"name": "Geral", "description": "Endpoints gerais e informações da API"}
    ],
    swagger_ui_parameters={"persistAuthorization": True}
)

# Montar arquivos estáticos
app.mount("/static", StaticFiles(directory="front_scents"), name="frontend")

@app.get("/", response_class=HTMLResponse)
async def web_view():
    with open("front_scents/index.html") as f:
        return HTMLResponse(content=f.read())

from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator, EmailStr
from passlib.context import CryptContext
import shutil
import os
import jwt
import datetime
import re
import secrets
import time
from typing import Dict, Optional, List
from enum import Enum
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Configurações básicas
import os
from dotenv import load_dotenv

# Carregar variáveis de ambiente
load_dotenv()

# Obter chaves secretas do ambiente ou usar valores padrão apenas para desenvolvimento
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))  # Reduzido para 30 minutos
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "uploads")
MAX_FILE_SIZE = int(os.getenv("MAX_FILE_SIZE", str(50 * 1024 * 1024)))  # 50MB

# Gerenciador de senhas seguras (bcrypt)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Configuração do rate limiter
limiter = Limiter(key_func=get_remote_address)

# Criando a API com configuração para documentação personalizada

# Configurações para servir documentação HTML personalizada
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import os

# Criar diretório para templates se não existir
os.makedirs("templates", exist_ok=True)
templates = Jinja2Templates(directory="templates")


# Criar diretório para arquivos estáticos
os.makedirs("static", exist_ok=True)

# Montar diretório estático
app.mount("/static", StaticFiles(directory="static"), name="static")

# Rota para documentação da API
@app.get(
    "/api-docs", 
    response_class=HTMLResponse,
    summary="Documentação da API",
    description="Página de documentação da API Scents",
    tags=["Geral"]
)
async def api_docs(request: Request):
    """
    Fornece uma página de documentação HTML personalizada e didática
    """
    return templates.TemplateResponse(
        "api_docs.html", 
        {"request": request, "api_title": app.title, "api_version": app.version}
    )

# Configurar favicon personalizado
@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return StaticFiles(directory="static")(Request(scope={"type": "http", "path": "/favicon.ico"}))

# Configurar URLs de documentação
app.docs_url = None  # Desabilitar a rota padrão do Swagger
app.redoc_url = None  # Desabilitar o ReDoc também

# Adicionar um endpoint de informações gerais da API
@app.get(
    "/info", 
    summary="Informações da API",
    description="Retorna informações gerais sobre a API",
    tags=["Geral"]
)
def api_info():
    """
    Retorna informações gerais da API.
    """
    return {
        "title": app.title,
        "description": app.description,
        "version": app.version,
        "documentation": {
            "message": "Documentação desabilitada"
        }
    }

# Rota raiz
@app.get(
    "/",
    summary="Página inicial",
    description="Retorna mensagem de boas-vindas",
    tags=["Geral"]
)
def read_root():
    return {"message": "Bem-vindo à API Scents. Acesse /api-docs para visualizar a documentação completa da API."}

# Adiciona middleware CORS para segurança
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Handler para rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Middleware para logging e segurança
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time

    # Adicionar headers de segurança
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # Log de tempo de resposta
    response.headers["X-Process-Time"] = str(process_time)

    return response

# Simulação de banco de dados
users_db: Dict[str, str] = {}  # Usuários armazenados com senhas hashadas
ads_db: Dict[int, dict] = {}  # Anúncios cadastrados
views_db: Dict[int, int] = {}  # Contagem de visualizações
sessions_db: Dict[str, dict] = {}  # Sessões ativas

# Dependência de autenticação com OAuth2
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="login",
    auto_error=False  # Permite documentação sem autenticação
)

# Função alternativa para usar em endpoints onde a autenticação não deve bloquear a documentação
def get_optional_token(token: str = Depends(oauth2_scheme)):
    return token

# Modelos de dados
class UserRole(str, Enum):
    """Roles de usuário para controle de acesso"""
    ADMIN = "admin"
    USER = "user"

class User(BaseModel):
    """
    Modelo de usuário para registro e autenticação
    """
    username: str = Field(..., description="Nome de usuário único", example="usuario123")
    password: str = Field(..., description="Senha do usuário (será armazenada com hash)", example="Senha_Segura123")
    email: Optional[EmailStr] = Field(None, description="Email do usuário", example="usuario@exemplo.com")
    role: UserRole = Field(default=UserRole.USER, description="Role do usuário")

    @field_validator('username')
    @classmethod
    def username_alphanumeric(cls, v):
        if not re.match(r'^[a-zA-Z0-9_]{3,20}$', v):
            raise ValueError('Username deve ter entre 3 e 20 caracteres e conter apenas letras, números e underscore')
        return v

    @field_validator('password')
    @classmethod
    def password_strength(cls, v):
        if len(v) < 8:
            raise ValueError('Senha deve ter pelo menos 8 caracteres')
        if not re.search(r'[A-Z]', v):
            raise ValueError('Senha deve conter pelo menos uma letra maiúscula')
        if not re.search(r'[a-z]', v):
            raise ValueError('Senha deve conter pelo menos uma letra minúscula')
        if not re.search(r'[0-9]', v):
            raise ValueError('Senha deve conter pelo menos um número')
        return v

    model_config = {
        "json_schema_extra": {
            "example": {
                "username": "usuario123",
                "password": "Senha_Segura123",
                "email": "usuario@exemplo.com",
                "role": "user"
            }
        }
    }

# Token com jti para permitir revogação
def generate_jti():
    return secrets.token_hex(16)

# Tokens revogados (em produção, use Redis ou banco de dados)
revoked_tokens = set()

# Função para criar token JWT
def create_access_token(username: str, role: str = UserRole.USER):
    jti = generate_jti()
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": username,
        "exp": expire,
        "iat": datetime.datetime.utcnow(),
        "jti": jti,
        "role": role
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

# Função para revogar um token
def revoke_token(jti: str):
    revoked_tokens.add(jti)

# Função para verificar token JWT
def verify_token(token: str, required_role: UserRole = None):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        jti: str = payload.get("jti")
        role: str = payload.get("role", UserRole.USER)

        if username is None:
            raise HTTPException(status_code=401, detail="Token inválido")

        if jti in revoked_tokens:
            raise HTTPException(status_code=401, detail="Token revogado")

        # Verificar role se necessário
        if required_role and role != required_role and role != UserRole.ADMIN:
            raise HTTPException(status_code=403, detail="Permissão insuficiente")

        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Erro na validação do token")

# Função para hashear senha
def hash_password(password: str):
    return pwd_context.hash(password)

# Função para verificar senha hashada
def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

# Endpoint para registro de usuários
@app.post(
    "/register",
    response_model=dict,
    status_code=201,
    summary="Registra um novo usuário",
    description="Cria um novo usuário com username, password, email e role",
    responses={
        201: {"description": "Usuário registrado com sucesso"},
        400: {"description": "Usuário já existe ou dados inválidos"},
        429: {"description": "Muitas requisições, tente novamente depois"}
    },
    tags=["Autenticação"]
)
@limiter.limit("5/minute")  # Limite de 5 tentativas por minuto
def register(user: User, request: Request):
    if user.username in users_db:
        raise HTTPException(status_code=400, detail="Usuário já existe")

    # Armazenar detalhes do usuário
    users_db[user.username] = {
        "password": hash_password(user.password),
        "email": user.email,
        "role": user.role,
        "created_at": datetime.datetime.utcnow().isoformat()
    }

    return {"message": "Usuário registrado com sucesso"}

# Endpoint para login e geração de token JWT
@app.post(
    "/login",
    response_model=dict,
    summary="Login de usuário",
    description="Autentica um usuário e retorna token JWT",
    responses={
        200: {"description": "Login bem-sucedido, retorna token de acesso"},
        401: {"description": "Credenciais inválidas"},
        429: {"description": "Muitas requisições, tente novamente depois"}
    },
    tags=["Autenticação"]
)
@limiter.limit("10/minute")  # Limite de 10 tentativas por minuto
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    user_data = users_db.get(form_data.username)

    if not user_data or not verify_password(form_data.password, user_data.get("password")):
        # Log da tentativa de login
        print(f"Tentativa de login falha para usuário: {form_data.username}, IP: {get_remote_address(request)}")

        # Adiciona um pequeno delay para dificultar ataques de força bruta
        time.sleep(1)

        raise HTTPException(status_code=401, detail="Credenciais inválidas")

    # Obter a role do usuário
    role = user_data.get("role", UserRole.USER)

    # Criar token com a role do usuário
    token = create_access_token(form_data.username, role)

    # Registrar a sessão
    sessions_db[token] = {
        "username": form_data.username,
        "login_time": datetime.datetime.utcnow().isoformat(),
        "expire_time": (datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).isoformat(),
        "ip": get_remote_address(request)
    }

    return {
        "access_token": token, 
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user_role": role
    }

# Endpoint para envio de anúncios
@app.post(
    "/upload",
    response_model=dict,
    summary="Upload de anúncio",
    description="Faz upload de arquivo MP3/MP4 (máx. 50MB)",
    responses={
        200: {"description": "Upload bem-sucedido"},
        400: {"description": "Formato inválido ou arquivo muito grande"},
        401: {"description": "Token inválido ou expirado"},
        500: {"description": "Erro interno ao processar o arquivo"}
    },
    tags=["Anúncios"]
)
async def upload_ad(
    file: UploadFile = File(..., description="Arquivo MP3 ou MP4 a ser processado"),
    token: str = Depends(get_optional_token)
):
    verify_token(token)  

    allowed_extensions = {".mp4", ".mp3"}
    ext = os.path.splitext(file.filename)[1].lower()

    if ext not in allowed_extensions:
        raise HTTPException(status_code=400, detail="Formato de arquivo não permitido. Use .mp4 ou .mp3.")

    # Certifique-se de que o diretório de uploads existe
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    try:
        file_location = f"{UPLOAD_DIR}/{file.filename}"
        with open(file_location, "wb") as buffer:
            # Leia o arquivo em chunks para evitar problemas de memória
            contents = await file.read()
            buffer.write(contents)

        # Verifica tamanho do arquivo após salvá-lo
        file_size = os.path.getsize(file_location)
        if file_size > MAX_FILE_SIZE:
            os.remove(file_location)  # Remove o arquivo se for muito grande
            raise HTTPException(status_code=400, detail="Arquivo muito grande. Máximo permitido é 50MB.")

        ad_id = len(ads_db) + 1
        ads_db[ad_id] = {"filename": file.filename, "path": file_location, "scents_applied": False}

        return {"message": "Anúncio enviado com sucesso", "ad_id": ad_id}

    except Exception as e:
        # Fornece detalhes do erro para facilitar a depuração
        raise HTTPException(status_code=500, detail=f"Erro ao processar o arquivo: {str(e)}")

# Aplicação do Scents ao anúncio
@app.post(
    "/apply-scents/{ad_id}",
    response_model=dict,
    summary="Aplicar Scents ao anúncio",
    description="Aplica a tecnologia Scents ao anúncio enviado previamente",
    responses={
        200: {"description": "Scents aplicado com sucesso"},
        401: {"description": "Token inválido ou expirado"},
        404: {"description": "Anúncio não encontrado"}
    },
    tags=["Anúncios"]
)
def apply_scents(
    ad_id: int = Path(..., description="ID do anúncio a ser processado", gt=0),
    token: str = Depends(get_optional_token)
):
    """
    Aplica a tecnologia Scents ao anúncio enviado

    - **ad_id**: ID do anúncio obtido no upload
    - **token**: Token JWT obtido no login

    Retorna confirmação de que o Scents foi aplicado ao anúncio.
    """
    verify_token(token)  

    if ad_id not in ads_db:
        raise HTTPException(status_code=404, detail="Anúncio não encontrado")

    ads_db[ad_id]["scents_applied"] = True
    return {"message": "Scents aplicado ao anúncio", "ad_id": ad_id}

# Endpoint para logout (revogação de token)
@app.post(
    "/logout",
    response_model=dict,
    summary="Logout de usuário",
    description="Revoga o token JWT atual",
    responses={
        200: {"description": "Logout bem-sucedido"},
        401: {"description": "Token inválido ou expirado"}
    },
    tags=["Autenticação"]
)
def logout(token: str = Depends(get_optional_token)):
    """
    Revoga o token JWT atual

    - **token**: Token JWT obtido no login

    Retorna uma mensagem de confirmação quando o logout é bem-sucedido.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        jti = payload.get("jti")

        if jti:
            revoke_token(jti)

        if token in sessions_db:
            del sessions_db[token]

        return {"message": "Logout realizado com sucesso"}
    except Exception:
        raise HTTPException(status_code=401, detail="Token inválido")

# Obter link do anúncio processado
@app.get(
    "/ad/{ad_id}",
    response_model=dict,
    summary="Visualizar anúncio",
    description="Obtém informações do anúncio e registra uma visualização",
    responses={
        200: {"description": "Informações do anúncio retornadas"},
        404: {"description": "Anúncio não encontrado"}
    },
    tags=["Visualização"]
)
def get_ad(
    ad_id: int = Path(..., description="ID do anúncio a ser visualizado", gt=0)
):
    """
    Visualiza um anúncio e registra a visualização

    - **ad_id**: ID do anúncio obtido no upload

    Retorna informações sobre o anúncio e incrementa o contador de visualizações.
    """
    if ad_id not in ads_db:
        raise HTTPException(status_code=404, detail="Anúncio não encontrado")

    views_db[ad_id] = views_db.get(ad_id, 0) + 1

    return {
        "ad_id": ad_id, 
        "filename": ads_db[ad_id]["filename"], 
        "scents_applied": ads_db[ad_id]["scents_applied"],
        "views": views_db[ad_id]
    }

# Estatísticas do anúncio
@app.get(
    "/stats/{ad_id}",
    response_model=dict,
    summary="Estatísticas do anúncio",
    description="Obtém estatísticas de visualização do anúncio",
    responses={
        200: {"description": "Estatísticas retornadas com sucesso"},
        401: {"description": "Token inválido ou expirado"},
        404: {"description": "Anúncio não encontrado"}
    },
    tags=["Estatísticas"]
)
def get_stats(
    ad_id: int = Path(..., description="ID do anúncio para consultar estatísticas", gt=0),
    token: str = Depends(get_optional_token)
):
    """
    Obtém estatísticas de visualização do anúncio

    - **ad_id**: ID do anúncio obtido no upload
    - **token**: Token JWT obtido no login

    Retorna o número de visualizações do anúncio.
    """
    verify_token(token)  

    if ad_id not in ads_db:
        raise HTTPException(status_code=404, detail="Anúncio não encontrado")

    return {"ad_id": ad_id, "views": views_db.get(ad_id, 0)}

# Criar diretório para uploads se não existir
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Inicializar o servidor
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=3005, log_level="info")