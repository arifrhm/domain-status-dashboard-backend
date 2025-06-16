from pydantic_settings import BaseSettings
import secrets
from typing import List


class Settings(BaseSettings):
    PROJECT_NAME: str = "Email Security Dashboard"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # JWT Settings
    SECRET_KEY: str = secrets.token_urlsafe(32)
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 8  # 8 days
    
    # Database
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str
    POSTGRES_DB: str
    POSTGRES_HOST: str
    POSTGRES_PORT: str
    
    @property
    def DATABASE_URL(self) -> str:
        return f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
    
    # CORS
    BACKEND_CORS_ORIGINS: List[str] = ["*"]
    
    # DNS Settings
    DNS_TIMEOUT: float = 5.0
    DNS_LIFETIME: float = 5.0
    DNS_TRIES: int = 3
    DNS_NAMESERVERS: str = "8.8.8.8,8.8.4.4"
    
    @property
    def DNS_NAMESERVER_LIST(self) -> List[str]:
        return [ns.strip() for ns in self.DNS_NAMESERVERS.split(",")]
    
    # Application Settings
    APP_PORT: int = 8000
    APP_HOST: str = "0.0.0.0"
    
    # Environment
    DEBUG: bool = False
    ENVIRONMENT: str = "production"
    
    class Config:
        case_sensitive = True
        env_file = ".env"


settings = Settings() 