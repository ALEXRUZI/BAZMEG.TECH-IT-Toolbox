# IT Toolbox | Bazmeg.Tech

A browser-based toolbox for common sysadmin, network, Linux, DNS, TLS, web, and developer tasks.

> This is an AI-assisted project. Code, structure, and documentation are built with help from AI, but the project is manually reviewed, tested, and maintained.

The goal is to keep everyday infrastructure helpers in one simple web app: generate firewall commands, inspect DNS records, check TLS certificates, review HTTP headers, calculate transfer times, generate passwords and secrets, create CSRs, convert timestamps, and format data.

The project uses a frontend/backend split. Tools that can safely run in the browser stay browser-side. Network inspection tools use a backend API because browsers cannot directly perform those checks safely or reliably.

## Status

### Browser-side tools

These tools run fully in the browser:

- Password / secret generator
- Firewalld generator
- UFW generator
- nftables generator
- chmod calculator
- Cron generator
- Epoch and Unix timestamp converter
- Data Transfer Calculator
- Units of information calculator
- CSR Generator
- Base64 / URL encode
- JSON / YAML formatter

### Backend-backed tools

These tools require the backend API:

- DNS Checker
- HTTP Header Checker
- TLS / SSL Certificate Checker

### Planned or future tools

- RDAP / WHOIS lookup
- SMTP banner checker
- Subnet calculator

## Privacy and Local Processing

Tools that handle sensitive generated data are designed to run locally in the browser where possible.

The CSR Generator creates the private key, public key, and CSR on the client device. No key material is sent to a server.

The Password / Secret Generator also runs locally in the browser.

Network inspection tools such as DNS Checker, HTTP Header Checker, and TLS / SSL Certificate Checker use the backend API because browsers cannot directly perform those checks safely or reliably.

## Tech Stack

### Frontend

- Vite
- React
- TypeScript
- Tailwind CSS

### Backend

- Node.js
- Native Node test runner

## Run Locally

The project has separate frontend and backend folders.

### Start the backend

PowerShell example:

```powershell
cd C:\Users\<your-user>\Documents\BAZMEG.TECH-IT-Toolbox\it-toolbox\backend

npm install

$env:BACKEND_SECRET = "dev-secret"

"Backend secret is: $($env:BACKEND_SECRET)"

node .\src\server.mjs
```

The backend listens locally on:

```text
http://127.0.0.1:3001
```

The `dev-secret` value is for local development only. Do not use it in production.

### Test the backend

Open a second PowerShell window and run:

```powershell
$Secret = "dev-secret"

Invoke-RestMethod `
  -Uri "http://127.0.0.1:3001/api/ping" `
  -Headers @{ "X-Toolbox-Backend-Secret" = $Secret }
```

A successful response confirms that the backend is running and the local secret header is accepted.

### Start the frontend

PowerShell example:

```powershell
cd C:\Users\<your-user>\Documents\BAZMEG.TECH-IT-Toolbox\it-toolbox\frontend

npm install

npm run dev
```

Open the URL printed by Vite, usually:

```text
http://localhost:5173
```

## Build

### Frontend

```powershell
cd frontend

npm install

npm run typecheck

npm run build
```

### Backend

```powershell
cd backend

npm install

npm test
```

Backend syntax check example:

```powershell
node --check .\src\server.mjs
```

## Deployment

Target frontend URL:

```text
https://toolbox.bazmeg.tech
```

The frontend is deployed as a static web app.

The backend is deployed separately because DNS lookup, HTTP header inspection, TLS certificate inspection, redirects, and similar checks require server-side network access.

Production secrets must be stored outside the repository, for example in server environment variables or platform secret storage.