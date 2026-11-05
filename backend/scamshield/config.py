
import os


class Config:
    MAX_URL_LENGTH = 2048
    MAX_MESSAGE_LENGTH = 10000

    JSON_SORT_KEYS = False

    FRONTEND_ORIGIN = os.getenv(
        "FRONTEND_ORIGIN",
        "http://127.0.0.1:5173"
    )
