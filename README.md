# Cirpman Homes — website + backend

A Node.js server with a SQLite database. **No npm packages to install.**

## Run it

Requires **Node.js 22.5 or newer** (https://nodejs.org).

    cd cirpman-app
    ADMIN_PASSWORD="choose-a-strong-password" npm start      # macOS / Linux
    # Windows PowerShell:  $env:ADMIN_PASSWORD="choose-a-strong-password"; npm start

Open http://localhost:3000. Admin button -> log in with the password you set.
If you don't set `ADMIN_PASSWORD`, the first-run password is `Cirpman@2026` — change it immediately under Admin -> Settings.
`ADMIN_PASSWORD` only matters the first time the database is created; after that, change it in Admin -> Settings.

Run the automated tests with `npm test`.

## Environment variables
| Name | Purpose |
|---|---|
| `PORT` | default 3000 |
| `DATA_DIR` | where `cirpman.db` and `uploads/` are kept (default `./data`). **Put this on a persistent disk and back it up.** |
| `ADMIN_PASSWORD` | initial admin password (first run only) |
| `PAYSTACK_SECRET` | Paystack secret key (or save it in Admin -> Settings) |
| `TOKEN_SECRET` | optional; otherwise generated and stored automatically |
| `TRUST_PROXY=1` | set when running behind nginx / a hosting router, so client IPs and HTTPS headers are right |

## Deploying
You need a host that runs Node (Render, Railway, Fly.io, a VPS, or cPanel "Setup Node.js App" if it offers Node 22+).
Plain PHP/static hosting will not work. Always serve over **HTTPS**, and attach a persistent disk/volume for `DATA_DIR`.
Paystack: add your keys in Admin -> Settings, and set the webhook URL in the Paystack dashboard to `https://YOUR-DOMAIN/api/paystack/webhook`.

## What the server does
* Prices are calculated on the server — the browser cannot change what a client pays.
* Passwords are hashed with scrypt; logins use signed tokens; login/registration/reset endpoints are rate-limited.
* Paystack payments are marked **Paid only after the server confirms them with Paystack** (amount, currency, reference).
* Commissions (direct / level 1 / level 2) are calculated on the server when a payment is confirmed or a consultant sale is approved.
* **Consultant deactivation is enforced on every request**: an Inactive consultant's existing login stops working immediately; they cannot log in or submit sales until reactivated. Only an admin session can do this.
* Gallery images/videos are saved on the server (`DATA_DIR/uploads`) and are visible to every visitor.
* Public visitors only ever receive estates, gallery, content and the Paystack *public* key. Clients, payments, consultants, sales and commissions require an admin (or the consultant's own) login.

## API (summary)
Public: `GET /api/public`, `POST /api/subscribe`, `POST /api/paystack/verify`, `POST /api/paystack/webhook`
Consultant: `POST /api/consultant/{register,login,reset-password}`, `GET /api/consultant/me`, `POST /api/consultant/sales`, `POST /api/consultant/sales/:id/resubmit`
Admin (Bearer token): `POST /api/admin/login`, `GET /api/admin/data`, `POST /api/admin/sync`, `PUT /api/admin/{content,settings}`, `POST /api/admin/upload`, `POST /api/admin/payments/:id/mark-paid`, `POST /api/admin/consultants/:id/{activate,deactivate,reactivate}`, `POST /api/admin/sales/:id/{approve,reject}`, `POST /api/admin/reset`

## Known limits / next steps
* Consultant "forgot password" still works by matching email + phone (as in the original site). Anyone who knows both can reset that account. Replace it with an emailed reset link once you have an email service.
* SQLite in one process is fine for a business site of this size; for heavy traffic move to PostgreSQL.
* `node:sqlite` is marked "experimental" by Node 22 (it works, and `npm start` hides the warning).
* Data entered in the old browser-only version is not migrated (it only existed in individual browsers). Re-enter estates/staff, or ask for an import script.
* Tailwind CSS, Font Awesome and Paystack are still loaded from their CDNs.
