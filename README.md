# Safeguard Nexus

Safeguard Nexus is a Flask-based visitor check-in and security monitoring system with optional face recognition, liveness checks, QR pre-registration, alerts, dashboards, and kiosk views.

## Requirements

- Python 3.11+ recommended
- A working camera for live face-recognition features
- Git LFS for `shape_predictor_68_face_landmarks.dat`

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

If the landmark model is missing or is only an LFS pointer, run:

```bash
git lfs install
git lfs pull
```

## Configuration

Set a strong admin password and Flask secret before starting:

```bash
export ADMIN_PASSWORD='replace-with-a-strong-password'
export SECRET_KEY='replace-with-a-long-random-secret'
```

Alert integrations are optional. Configure them with environment variables:

```bash
export TELEGRAM_BOT_TOKEN='your-bot-token'
export TELEGRAM_CHAT_ID='your-chat-id'
export SENDER_EMAIL='sender@example.com'
export SENDER_PASSWORD='email-app-password'
export ALERT_EMAIL='security@example.com'
```

Do not commit credentials, database files, visitor photos, or generated reports.

## Run

```bash
source .venv/bin/activate
python app.py
```

Open <http://127.0.0.1:5000>. The dashboard is available at `/dashboard` and redirects to `/login` until authenticated.

## Main Components

- `app.py`: Flask server, API routes, database setup, authentication, and visitor workflows
- `dashboard.py`: optional CustomTkinter desktop dashboard
- `backup.py`: legacy desktop implementation and backup utilities
- `templates/`: web pages
- `known_faces/`: reference images used to build face encodings
- `shape_predictor_68_face_landmarks.dat`: dlib landmark model managed by Git LFS

## Development Checks

```bash
python -m py_compile app.py dashboard.py backup.py
python -m json.tool settings.json >/dev/null
```

Before deploying, rotate any credential that has ever appeared in Git history and use a private repository or a history-cleaning procedure for sensitive data.
