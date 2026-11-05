# ScamShield AI Backend

ScamShield AI uses a Python Flask backend to perform preliminary screening of URLs and text messages for potentially suspicious indicators.

## Current capabilities

- Analyze submitted URLs.
- Analyze suspicious SMS and message content.
- Identify suspicious patterns using rule-based checks.
- Return preliminary risk assessments: LOW, MEDIUM, or HIGH.
- Provide warnings and flagged indicators.
- Validate incoming API requests.

## API endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | /api/health | Check backend availability |
| POST | /api/analyze-url | Analyze a URL |
| POST | /api/analyze-message | Analyze message content |

## Technology

- Python
- Flask
- Flask-CORS
- Rule-based URL and message analysis

## Run locally

Install dependencies:

    python -m pip install -r requirements.txt

Start the server:

    python app.py

The backend runs at http://127.0.0.1:5000.

## Run tests

    python -m unittest discover -s tests -v

## Important notice

ScamShield AI provides preliminary automated screening only. It does not guarantee that a URL or message is safe.

AI model integration and analysis history are not currently implemented.
