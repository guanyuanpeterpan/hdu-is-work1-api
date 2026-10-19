from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt

from app.database import (
    get_articles,
    get_user_by_username,
    init_db,
    insert_article,
)
from app.models import (
    ArticleCreate,
    ArticleResponse,
    LoginRequest,
    ProtectedDataResponse,
    TokenResponse,
)
from app.security import (
    create_access_token,
    decode_access_token,
    sanitize_xss,
    verify_password,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="HDU IS Secure REST API",
    description="Secure REST API demonstrating protection against OWASP Top 10 vulnerabilities",
    version="1.0.0",
    lifespan=lifespan,
)

security_scheme = HTTPBearer(auto_error=True)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(security_scheme),
) -> dict:
    """Dependency that extracts and validates Bearer JWT token."""
    token = credentials.credentials
    try:
        payload = decode_access_token(token)
        username: str | None = payload.get("sub")
        if not username:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload: missing subject",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token signature or format",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = get_user_by_username(username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


@app.post(
    "/auth/login",
    response_model=TokenResponse,
    summary="User login with bcrypt verification and JWT issuance",
)
def login(data: LoginRequest):
    """Authenticate user with bcrypt password verification and issue JWT access token."""
    user = get_user_by_username(data.username)
    if not user or not verify_password(data.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token({
        "sub": user["username"],
        "user_id": user["id"],
        "role": user["role"],
    })
    return TokenResponse(access_token=token)


@app.get(
    "/api/data",
    response_model=ProtectedDataResponse,
    summary="Protected data endpoint requiring valid JWT",
)
def get_protected_data(current_user: dict = Security(get_current_user)):
    """Return sensitive business data only to authenticated users with valid JWT."""
    return ProtectedDataResponse(
        status="success",
        current_user=current_user["username"],
        items=[
            {"id": 101, "metric": "Firewall Rule Status", "value": "Enforced"},
            {"id": 102, "metric": "Vulnerability Scan", "value": "Clean (Zero Critical)"},
            {"id": 103, "metric": "Active Sessions", "value": "Protected by JWT"},
        ],
    )


@app.post(
    "/api/articles",
    response_model=ArticleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create article with SQLi parameterized query and XSS HTML sanitization",
)
def create_article(
    data: ArticleCreate, current_user: dict = Security(get_current_user)
):
    """Create an article: sanitizes input against XSS, executes parameterized query against SQLi."""
    clean_title = sanitize_xss(data.title)
    clean_content = sanitize_xss(data.content)
    created = insert_article(clean_title, clean_content, current_user["id"])
    return ArticleResponse(**created)


@app.get(
    "/api/articles",
    response_model=list[ArticleResponse],
    summary="List all articles (protected by JWT)",
)
def list_articles(current_user: dict = Security(get_current_user)):
    """Retrieve all articles stored in the database."""
    articles = get_articles()
    return [ArticleResponse(**a) for a in articles]
