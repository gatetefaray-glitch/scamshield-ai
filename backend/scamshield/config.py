import os


class Config:
    MAX_URL_LENGTH = 2048
    MAX_MESSAGE_LENGTH = 10000

    # Maximum HTTP request body size: 64 KB
    MAX_CONTENT_LENGTH = 64 * 1024

    JSON_SORT_KEYS = False

    FRONTEND_ORIGIN = os.getenv(
        "FRONTEND_ORIGIN",
        "http://127.0.0.1:5173"
    )

    # Ollama configuration
    OLLAMA_BASE_URL = os.getenv(
        "OLLAMA_BASE_URL",
        "http://127.0.0.1:11434"
    )

    OLLAMA_MODEL = os.getenv(
        "OLLAMA_MODEL",
        "llama3.2:latest"
    )

    OLLAMA_TIMEOUT = int(
        os.getenv("OLLAMA_TIMEOUT", "30")
    )
