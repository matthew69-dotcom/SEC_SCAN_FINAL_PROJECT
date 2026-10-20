"""Centralized config loaded from .env"""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_version: str = "0.1.0"
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    database_url: str = "sqlite:///./dev.db"
    cors_origins: str = "http://localhost:5173"


settings = Settings()

# Sent on every outbound HTTP request the scanner makes. Site operators'
# bot policies (e.g. Wikimedia's User-Agent policy) require a contact URL;
# without it wikipedia.org answered HTTP 403 and the headers check graded an
# error page instead of the real site. Do NOT append a library token such as
# "python-httpx": Cloudflare (thaigov.go.th) and Imperva (chula.ac.th) then
# serve a block or challenge page. Some sites (mahidol.ac.th, Akamai) refuse
# every self-identifying bot; we do not disguise the scanner as a browser.
SCANNER_USER_AGENT = (
    "MFU-DomainSecurityChecker/0.1 "
    "(+https://github.com/matthew69-dotcom/SEC_SCAN_FINAL_PROJECT)"
)
