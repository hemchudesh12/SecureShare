# SecureShare — How to Run the Project

---

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.11+ | [python.org](https://python.org) |
| Redis | 5.0+ | WSL2 on Windows, or [Memurai](https://www.memurai.com/) |
| Git | any | For cloning the repo |

---

## Step 1 — Clone & Set Up

```bash
git clone https://github.com/your-username/secure_file_sharing.git
cd secure_file_sharing

python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Linux / Mac

pip install -r requirements.txt
```

---

## Step 2 — Create `.env` File

Create a file named `.env` in the project root with the following contents:

```env
SECRET_KEY=any-long-random-string-here

CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0

MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-gmail-app-password
```

> To get a Gmail App Password: Google Account → Security → 2-Step Verification → App Passwords

---

## Step 3 — Run (3 Terminals)

Open **three separate terminals**, all inside the project folder with the virtual environment activated.

### Terminal 1 — Flask Web Server
```bash
python app.py
```
✅ App runs at **http://127.0.0.1:5000**

### Terminal 2 — Celery Worker *(for async file uploads)*
```bash
celery -A worker:celery worker --loglevel=info
```

### Terminal 3 — Redis *(if not already running as a service)*
```bash
# WSL2 / Linux / Mac
redis-server

# Windows with Memurai — it runs as a Windows service automatically
# Check: netstat -ano | findstr :6379
```

---

## Step 4 — Create Admin Account *(first-time only)*

```bash
flask create-admin
# Enter username and password when prompted
```

---

## Quick Verification Checklist

- [ ] `http://127.0.0.1:5000` loads the login page
- [ ] Redis is running → `netstat -ano | findstr :6379` shows a LISTENING entry
- [ ] Celery terminal shows `[celery@...] ready`
- [ ] Register a user → OTP email is received
- [ ] Upload a file → progress bar appears (confirms Celery is working)

---

## Common Issues

| Problem | Fix |
|---|---|
| `redis.exceptions.ConnectionError` | Redis is not running — start it in Terminal 3 |
| OTP email not received | Check `MAIL_USERNAME` / `MAIL_PASSWORD` in `.env`; use a Gmail App Password, not your main password |
| Upload stuck at 0% | Celery worker is not running — start Terminal 2 |
| `ModuleNotFoundError` | Virtual environment not activated — run `venv\Scripts\activate` |
| Port 5000 already in use | Change port: `python app.py --port 5001` or kill the existing process |

---

*Python 3.11 · Flask 3.0 · Celery 5.3.6 · Redis 5.0.1 · AES-256-GCM*
