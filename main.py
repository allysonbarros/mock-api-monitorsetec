from fastapi import FastAPI, Depends, HTTPException, status, Header, Request,Form
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials, OAuth2PasswordBearer
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException
from typing import Annotated
from pydantic import BaseModel

from faker import Faker
fake = Faker()
Faker.seed(0)

app = FastAPI()

USERNAME = "usuario"
PASSWORD = "s3cr3t"
SIMPLE_TOKEN = "ffd25a96d536a91666233351fcdecebc"
CLIENT_ID = 'app_example'
CLIENT_SECRET = 'b1f8df2dede32e6c9723ed1896cd531e'

siglas_variaveis = [
    "NACE", "NDE", "NAVS", "NAPS", "NTE", "OAE", "OTI", "NTS", "NAPP", "NPPB", 
    "NAPPP", "NTAAA", "NCL", "NC", "TAFPPI", "PC", "PA", "DI", "C", "PTLT", "TPTI",
    "NSPP", "NS", "NL", "NA", "OCC", "OGM", "NTATT", "NPPA", "M", "NAr", "TC", "NEGAPI", 
    "NEAAPI", "NEGHI", "NEE", "NAPI", "NHI", "NAE", "NTEA", "NTAFPP", "NTCTT", "NEAHI", "NACCA", 
]

class User(BaseModel):
    username: str
    password: str


class OAuth2App(BaseModel):
    client_id: str
    client_secret: str
    grant_type: str = "client_credentials"


class JWTSettings(BaseModel):
    authjwt_secret_key: str = "s3cr3t"


@AuthJWT.load_config
def get_config():
    return JWTSettings()


@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(request: Request, exc: AuthJWTException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.message}
    )

def __get_dict_resposta():
    return {
        sigla: fake.random_number(digits=3) for sigla in siglas_variaveis
    }


def __get_token(authorization: Annotated[str | None, Header()] = None):    
    if authorization is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token não informado",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = authorization.split(" ")[1]
    
    if token != SIMPLE_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return token

# Rota de Teste

@app.get("/")
async def hello_world():
    return {"message": "Hello World"}

# Sem Autenticação

@app.get("/sem_autenticacao")
async def sem_autenticacao():
    return __get_dict_resposta()

# HTTP Basic

@app.get("/http_basic")
async def http_basic(credentials: HTTPBasicCredentials = Depends(HTTPBasic())):
    if credentials.username == USERNAME and credentials.password == PASSWORD:
        return __get_dict_resposta()
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais inválidas",
            headers={"WWW-Authenticate": "Basic"},
        )

# Simple Token

@app.get("/simple_token")
async def simple_token(token: str = Depends(__get_token)):
    return __get_dict_resposta()

# JWT

@app.post('/auth/jwt')
def login_jwt(user: User, Authorize: AuthJWT = Depends()):
    if user.username != USERNAME or user.password != PASSWORD:
        raise HTTPException(status_code=401,detail="Bad username or password")
    access_token = Authorize.create_access_token(subject=user.username)
    return {"access_token": access_token}


@app.get("/jwt")
async def jwt(auth: AuthJWT = Depends()):
    auth.jwt_required()
    return __get_dict_resposta()

# OAuth2

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/oauth2")

class OAuth2PasswordRequestFormCustom:
    def __init__(
        self,
        grant_type: str = "client_credentials",
        client_id: str = Form(..., alias="client_id"),
        client_secret: str = Form(..., alias="client_secret"),
    ):
        self.grant_type = grant_type
        self.client_id = client_id
        self.client_secret = client_secret

@app.post('/auth/oauth2')
def login_oauth(app: OAuth2PasswordRequestFormCustom = Depends(), Authorize: AuthJWT = Depends()):
    if app.client_id != CLIENT_ID or app.client_secret != CLIENT_SECRET:
        raise HTTPException(status_code=401,detail="Bad application credentials")
    access_token = Authorize.create_access_token(subject=app.client_id)
    return {"access_token": access_token, "token_type": "bearer" }


@app.get("/oauth2")
async def oauth2(token: str = Depends(oauth2_scheme)):
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais inválidas",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return __get_dict_resposta()