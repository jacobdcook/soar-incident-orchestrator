from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    SLACK_WEBHOOK_URL: str = ""
    AZURE_CLIENT_ID: str = ""
    AZURE_CLIENT_SECRET: str = ""
    AZURE_TENANT_ID: str = ""
    
    class Config:
        env_file = ".env"

settings = Settings()
