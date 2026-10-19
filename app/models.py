from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=50)
    password: str = Field(..., min_length=1, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 3600


class ArticleCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    content: str = Field(..., min_length=1, max_length=5000)


class ArticleResponse(BaseModel):
    id: int
    title: str
    content: str
    author: str
    created_at: str


class ProtectedDataResponse(BaseModel):
    status: str
    current_user: str
    items: list[dict]
