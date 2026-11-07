"""
PHANTOM Backend Configuration
Loads settings from environment variables with sensible defaults.
"""
from pydantic_settings import BaseSettings
from pydantic import Field
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # MongoDB
    mongodb_uri: str = Field(default="mongodb://localhost:27017", description="MongoDB connection URI")
    mongodb_db_name: str = Field(default="phantom", description="MongoDB database name")

    # Server
    host: str = Field(default="0.0.0.0", description="Server host")
    port: int = Field(default=8000, description="Server port")
    debug: bool = Field(default=False, description="Debug mode")
    log_level: str = Field(default="info", description="Logging level")

    # Rate Limiting
    rate_limit_requests: int = Field(default=100, description="Max requests per window")
    rate_limit_window_seconds: int = Field(default=60, description="Rate limit window in seconds")

    # Security
    max_redirects: int = Field(default=5, description="Maximum allowed redirects")
    request_timeout_seconds: int = Field(default=10, description="Request timeout")
    max_response_size_bytes: int = Field(default=10_485_760, description="Max response size (10MB)")

    # External API Keys (optional)
    virustotal_api_key: str = Field(default="", description="VirusTotal API key")
    shodan_api_key: str = Field(default="", description="Shodan API key")
    abuseipdb_api_key: str = Field(default="", description="AbuseIPDB API key")

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "case_sensitive": False}


@lru_cache()
def get_settings() -> Settings:
    """Return cached settings instance."""
    return Settings()
