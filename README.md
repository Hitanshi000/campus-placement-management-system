# Campus Placement Management System

A small full-stack campus placement portal. The browser page talks to a Python backend, which stores users, placement listings, applications, and sessions in a local SQLite database.

## Features

- Student and admin accounts
- Passwords stored as salted PBKDF2 hashes
- Server-side sessions in an HttpOnly cookie
- SQLite persistence for users, listings, and applications
- Admin controls for listings and application status
- A private invite code required to register admin accounts
- No third-party Python packages required

## Run locally on Windows

1. Install Python 3.10 or newer if it is not already installed.
2. Open PowerShell in this project folder.
3. Set a private admin invite code and start the backend:

   ```powershell
   $env:ADMIN_INVITE_CODE = "choose-a-long-private-code"
   python server.py
   ```

4. Open [http://127.0.0.1:8000](http://127.0.0.1:8000) in your browser.
5. Register an Admin account using the invite code. Register a Student account separately to try applying to placements.

The server creates `placement.db` and adds three sample companies on first run. Stop it with **Ctrl+C**. The database remains on your computer, so the accounts and applications will still be there next time.

## How it works

- `index.html` is the web interface.
- `server.py` serves the page and provides the `/api` endpoints.
- `placement.db` is created locally and ignored by Git.
- Set `PORT` to change the port. Set `PLACEMENT_DB` to store the database at another path.
- Admin registration is disabled unless `ADMIN_INVITE_CODE` is set in the server environment.

## Hosting and security limits

GitHub Pages can host static pages but cannot run this Python backend. To use the app online, deploy it on a Python-capable host with persistent disk storage for SQLite, keep `ADMIN_INVITE_CODE` private, and use HTTPS. Set `COOKIE_SECURE=1` when the site is served through HTTPS. The included `http.server` backend is intended for learning and demos; it is not hardened for production or real student records. Use a production web server and review security, backups, and privacy requirements before real deployment.

## Source and attribution

This repository builds on the supplied `Campus-Placement-Demo.html` and accompanying project materials. Confirm the original contributors' names and permission, and retain their credit when publishing or presenting the project. Add your own contributions and attribution here.
