# 🔐 SecureShare — Org-Scoped Encrypted File Sharing

> A production-grade, cryptographically secured file-sharing web application with end-to-end AES-256-GCM encryption, RSA-2048 digital signatures, and organisation-scoped access control.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Security Model](#security-model)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Configuration](#configuration)
- [Running the App](#running-the-app)
- [How It Works](#how-it-works)
- [API Endpoints](#api-endpoints)
- [Screenshots](#screenshots)
- [Security Comparison](#security-comparison)

---

## Overview

**SecureShare** is a self-hostable, end-to-end encrypted file sharing platform built with Python and Flask. It enforces **organisation-scoped access control** — only members of the same organisation can share files with one another.

Every file is:
- 🔒 **Encrypted at rest** using AES-256-GCM (chunk-based, authenticated)
- ✍️ **Signed by the sender** using RSA-2048/PSS + SHA-256
- ✅ **Signature verified before any byte is streamed** on download
- 📊 **Upload progress tracked in real time** via Celery async task + polling
- 📡 **Download counts updated live** via Server-Sent Events (no page reload)

---

## Features

### 🔑 Authentication
- User registration with **Email OTP verification** (6-digit, 5-minute expiry)
- Three registration modes: **Standalone**, **Create Organisation**, **Join Organisation**
- Account lockout after **10 failed login attempts** (15-minute cooldown)
- OTP lockout after **5 incorrect attempts**
- Secure password change that **re-encrypts the RSA private key envelope**

### 📁 File Management
- Async file upload via **Celery + Redis** — page never blocks
- Real-time upload **progress bar** (5% → 100%) with auto-redirect on completion
- **Per-recipient encryption** — each recipient gets their own RSA-wrapped AES key
- Set **expiry time** and **download limits** per share
- **Revoke access** for any recipient at any time
- File **access history** modal with per-event IP, timestamp, and verification status

### 📡 Real-Time Updates
- Download counts update **instantly** in the sender's browser via **Server-Sent Events (SSE)**
- No polling, no page reload — the counter changes the moment a recipient downloads

### 🛡️ Admin Panel
- Approve/reject user join requests for organisations
- View all organisation members and their activity
- Verify the **hash-chained audit log** (tamper detection)
- Organisation management (create, view members)

### 🔍 Signature Verification
- Standalone `/verify/<file_id>` endpoint
- Recomputes SHA-256 plaintext hash in memory (no disk write)
- Verifies RSA-PSS signature against sender's public key
- Logs result to `VerificationLog` with IP and timestamp

---

## Security Model

| Layer | Implementation |
|---|---|
| File Encryption | AES-256-GCM, 16 MB chunks, per-chunk nonce + auth tag |
| Key Wrapping | RSA-2048/OAEP — unique AES key wrapped per recipient |
| Digital Signatures | RSA-2048/PSS + SHA-256 — signed on upload, verified before download |
| Private Key Storage | PBKDF2-HMAC-SHA256 (390,000 iterations) + AES-256-CBC envelope |
| OTP Storage | SHA-256 hashed — plaintext OTP never persisted |
| Audit Log | Hash-chained (blockchain-style) — each entry hashes the previous |
| Session Cookies | HttpOnly, SameSite=Lax, 30-minute lifetime |
| Rate Limiting | Flask-Limiter on all auth endpoints |
| CSRF Protection | Flask-WTF on all state-mutating routes |
| Access Control | Organisation-scoped — cross-org access blocked at service layer |

---

## Tech Stack

| Component | Technology |
|---|---|
| Backend | Python 3.11+, Flask 3.0.0 |
| Database | SQLAlchemy 3.1.1 + SQLite (two separate DBs) |
| Cryptography | `cryptography >= 42.0.0` (hazmat primitives) |
| Password Hashing | bcrypt 4.1.2 |
| Async Tasks | Celery 5.3.6 |
| Message Broker | Redis 5.0.1 |
| CSRF | Flask-WTF 1.2.1 |
| Rate Limiting | Flask-Limiter 3.5.0 |
| Email | SMTP via smtplib (Gmail default) |
| Frontend | Jinja2 + Vanilla CSS + JavaScript |
| Real-Time | Server-Sent Events (SSE) |

---

## Project Structure

```
secure_file_sharing/
│
├── app.py                    # Flask application factory & CLI
├── config.py                 # Configuration (env-var loader)
├── extensions.py             # Shared extensions (db, csrf, limiter)
├── celery_app.py             # Standalone Celery instance
├── tasks.py                  # async_upload Celery task
├── worker.py                 # Celery worker entry point
├── otp_utils.py              # OTP generation, hashing, verification
├── email_utils.py            # OTP email delivery via SMTP
│
├── models/
│   ├── auth_models.py        # User, Organization, OrgRequest, AuditLog
│   └── file_models.py        # File, FileShare, AccessLog, VerificationLog
│
├── routes/
│   ├── auth_routes.py        # register, OTP verify, login, password change
│   ├── file_routes.py        # upload, download, verify, revoke, SSE stream
│   └── admin_routes.py       # dashboard, org management, audit verification
│
├── services/
│   ├── crypto_service.py     # CryptoUtils (AES-GCM, RSA, PBKDF2)
│   ├── auth_service.py       # Registration, authentication, key management
│   ├── file_service.py       # process_upload, process_download, revoke
│   ├── access_control.py     # File access permission enforcement
│   ├── logging_service.py    # Hash-chained audit log
│   └── sse_bus.py            # Server-Sent Events pub/sub bus
│
├── utils/
│   └── helpers.py            # Login decorators, org member helpers
│
├── templates/                # 16 Jinja2 HTML templates
├── static/                   # CSS, JS, static assets
├── storage/
│   ├── files/                # Encrypted file blobs (UUID-named)
│   └── keys/                 # Key storage directory
│
├── requirements.txt
├── .env                      # Environment variables (not committed)
└── README.md
```

---

## Getting Started

### Prerequisites

- Python 3.11+
- Redis (running on `localhost:6379`)
  - **Windows**: Use [Memurai](https://www.memurai.com/) or WSL2 with Redis
  - **Linux/Mac**: `sudo apt install redis-server` or `brew install redis`

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/secure_file_sharing.git
cd secure_file_sharing
```

### 2. Create a Virtual Environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / Mac
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables

Create a `.env` file in the project root (copy from the template below):

```env
SECRET_KEY=your-very-secret-flask-key

# Redis (Celery broker & result backend)
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0

# Email (for OTP delivery)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password

# OTP & Login settings
OTP_EXPIRY_MINUTES=5
MAX_OTP_ATTEMPTS=5
MAX_LOGIN_ATTEMPTS=10
```

> ⚠️ **Never commit your `.env` file to GitHub.** It is already included in `.gitignore`.

---

## Running the App

You need **3 terminals** running simultaneously:

### Terminal 1 — Flask Web Server

```bash
python app.py
```

App will be available at: `http://127.0.0.1:5000`

### Terminal 2 — Celery Worker (for async uploads)

```bash
celery -A worker:celery worker --loglevel=info
```

### Terminal 3 — Redis (if not running as a service)

```bash
# WSL2 / Linux / Mac
redis-server

# Windows (Memurai runs as a service automatically)
```

---

## Configuration

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | — | Flask session signing key (required) |
| `CELERY_BROKER_URL` | `redis://localhost:6379/0` | Redis URL for Celery broker |
| `CELERY_RESULT_BACKEND` | `redis://localhost:6379/0` | Redis URL for task results |
| `MAIL_SERVER` | `smtp.gmail.com` | SMTP server for OTP emails |
| `MAIL_PORT` | `587` | SMTP port |
| `MAIL_USERNAME` | — | Sender email address |
| `MAIL_PASSWORD` | — | SMTP app password |
| `OTP_EXPIRY_MINUTES` | `5` | OTP validity window |
| `MAX_OTP_ATTEMPTS` | `5` | Max OTP verification attempts |
| `MAX_LOGIN_ATTEMPTS` | `10` | Failed logins before account lock |

---

## How It Works

### Upload Flow

```
1. User selects file + recipients → submits form (fetch, no page reload)
2. Flask saves temp file → queues Celery task → returns 202 + task_id
3. Celery worker:
     5%  → Starting encryption
    30%  → AES-256-GCM encrypt (16 MB chunks)
    60%  → RSA-OAEP wrap key per recipient
    85%  → Save DB records (File + FileShare rows)
   100%  → Done
4. Browser polls /upload-status/<task_id> every 2 seconds
5. Progress bar hits 100% → auto-redirects to /my-files
```

### Download Flow (4-Step Security Pipeline)

```
Step 1 → Decrypt AES session key with recipient's RSA private key
Step 2 → Recompute SHA-256 of plaintext in memory (no disk write)
Step 3 → Verify sender's RSA-PSS signature (ABORT if invalid)
Step 4 → Stream decrypted bytes to browser (generator, O(16MB) RAM)
```

### Real-Time Download Counter (SSE)

```
Recipient downloads a file
  → file_service increments download_count → commits to DB
  → sse_bus.notify_download_update(owner_id, ...)
  → Owner's open browser tab receives SSE event instantly
  → Counter updates with a green flash — no page reload
```

---

## API Endpoints

| Method | Route | Description |
|---|---|---|
| `POST` | `/upload` | Async file upload (returns 202 + task_id) |
| `GET` | `/upload-status/<task_id>` | Celery task progress poll |
| `GET` | `/download/<file_id>` | Secure streaming download |
| `GET` | `/verify/<file_id>` | Standalone signature verification |
| `POST` | `/revoke-access` | Revoke a recipient's access |
| `GET` | `/file-access-history/<file_id>` | JSON access log for a file |
| `GET` | `/sse/download-counts` | SSE stream for real-time download counts |
| `GET` | `/download-counts` | JSON snapshot of current download counts |
| `GET` | `/my-files` | Files uploaded by current user |
| `GET` | `/shared-with-me` | Files shared with current user |
| `GET` | `/dashboard` | User dashboard with stats |

---

## Security Comparison

| Feature | Google Drive | Dropbox | Tresorit | **SecureShare** |
|---|:---:|:---:|:---:|:---:|
| Client-side encryption | ✗ | ✗ | ✓ | ✅ |
| Authenticated encryption (GCM) | ✗ | ✗ | ✗ | ✅ |
| Per-file sender digital signature | ✗ | ✗ | ✗ | ✅ |
| Signature verified on every download | ✗ | ✗ | ✗ | ✅ |
| Zero plaintext written to server disk | ✗ | ✗ | ✓ | ✅ |
| Org-scoped sharing enforcement | Partial | Partial | ✗ | ✅ |
| Tamper-evident hash-chained audit log | ✗ | ✗ | ✗ | ✅ |
| Per-recipient download limits | ✗ | ✗ | ✗ | ✅ |
| Immediate access revocation | Partial | Partial | ✓ | ✅ |
| Real-time download count updates (SSE) | ✗ | ✗ | ✗ | ✅ |
| Fully auditable open codebase | ✗ | ✗ | ✗ | ✅ |
| Self-hostable | ✗ | ✗ | ✗ | ✅ |

---

## Creating an Admin Account

```bash
flask create-admin
# Enter username and password when prompted
```

---

## License

This project is open source and available under the [MIT License](LICENSE).

---

## Author

Built with 🔐 for secure, auditable, end-to-end encrypted file sharing.
