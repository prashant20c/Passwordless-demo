# Passwordless Demo

A minimal password-less authentication demo showcasing a multi-channel login experience:

- **Frontend**: Vite + Vue 3 + Tailwind CSS single-page app for registration, login, and account views.
- **Backend**: Core PHP API that coordinates challenges and JWT issuance.
- **Mock Data Store**: JSON Server providing REST persistence for users, devices, and login requests.
- **Device App**: Python Tkinter GUI that holds a device-specific private key and approves login challenges.

This repo stitches the pieces together so you can experience a password-less login from end to end.

## Project Structure

```
passwordless-demo/
  README.md
  .env.example
  sample_data.md
  frontend/        # Vite + Vue 3 + Tailwind SPA
  backend-php/     # Core PHP API (public/ as web root)
  mock-api/        # JSON Server mock storage
  device-gui/      # Python Tkinter approval app
```

Each sub-folder has its own README snippets below.

## Prerequisites

- Node.js 18+
- npm 9+
- PHP 8.1+ with the `sodium` extension enabled
- Composer 2+
- Python 3.10+
- `pip`

## Mock API (JSON Server)

```
cd mock-api
npm install
npm run dev
```

This runs JSON Server at <http://localhost:4000>. The script is defined in `mock-api/package.json` and watches `db.json` for changes.

## Backend PHP API

```
cd backend-php
composer install
cp .env.example .env
php -S localhost:8080 -t public
```

Environment variables in `.env`:

```
JSON_SERVER_BASE=http://localhost:4000
JWT_SECRET=dev_secret_change_me
CORS_ORIGIN=http://localhost:5173
LOGIN_RATE_PER_MIN=5
LOGIN_TIMEOUT_SECONDS=60
```

The PHP built-in server exposes the API at <http://localhost:8080>.

## Frontend SPA (Vite + Vue + Tailwind)

```
cd frontend
npm install
cp .env.example .env
npm run dev
```

The development server runs at <http://localhost:5173> and expects the backend at `VITE_API_BASE`.

## Device GUI (Python + Tkinter)

```
cd device-gui
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

On first run the GUI prompts for email, password, and a device name, then generates an Ed25519 keypair that remains in `state.json`. For demo purposes the keys are stored in plain text; production apps must use secure enclaves or OS keychains.

## Sample Flow

1. Start JSON Server, backend PHP server, and the frontend dev server.
2. Launch the Python device GUI and link the device using your email/password.
3. Register a new user on the web app (or use an existing user from `sample_data.md`).
4. On the login page, submit your email; the device receives a challenge.
5. Approve the challenge in the device app; the web app observes approval, stores the JWT, and loads the account view.

## Notes

- This project favors clarity over production hardening. The challenge expiry, rate limits, and key storage are simplified for demonstration purposes.
- Sodium must be enabled in PHP. If you encounter `Sodium extension missing`, install/enable it (e.g., `sudo apt install php-sodium`).

Enjoy experimenting with password-less flows!
