# SSC — Securitatea API-urilor (JWT + OAuth 2.0)

## Prerequisites

1. **Node.js** (v18+) — https://nodejs.org/
2. **VS Code** — https://code.visualstudio.com/
3. **REST Client** (extensie VS Code) — cauta "REST Client" de Huachao Mao in Extensions

## Setup

### Windows

```bash
cd ssc
copy .env.example .env
npm install
npm run dev
```

### Linux

Daca `npm install` da erori de compilare, instaleaza mai intai:
```bash
sudo apt install build-essential python3
```

Apoi:
```bash
cd ssc
cp .env.example .env
npm install
npm run dev
```

Serverul porneste pe `http://localhost:3000`.

## Testare

Deschide `tests/test.rest` in VS Code. Dai click pe **Send Request** deasupra fiecarui request, in ordine. Dupa login, copiezi `accessToken` si `refreshToken` din raspuns si le lipesti in request-urile urmatoare in locul placeholderelor.

## Structura

```
server.js           — Express server + helmet + rate limiting + CORS
middleware/auth.js  — JWT verify + role-based access control
routes/auth.js      — register, login, refresh, logout, Google OAuth
routes/articles.js  — CRUD protejat (public / auth / admin)
routes/admin.js     — user management (admin only)
db/                 — SQLite + migrations
tests/test.rest     — toate requesturile pentru demo
```
