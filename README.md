# IT Toolbox | Bazmeg.Tech

A browser-based toolbox for common sysadmin, network, Linux, and developer tasks.

The goal is to keep everyday infrastructure helpers in one simple frontend: generate firewall commands, convert data units, format text, calculate schedules, and create CSRs without sending sensitive input to a server.

## Status

Some tools are fully working in the browser. Other tools are currently marked as **planned** because they require a backend server to perform network-side checks safely and reliably. That backend is in the works.

Working browser-side tools include:

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
- JSON/YAML formatter

Planned backend-backed tools include:

- DNS checker
- HTTP headers
- TLS cert checker
- RDAP / WHOIS lookup
- Redirect checker
- SMTP banner checker
- Subnet calculator

## CSR Generator

The CSR Generator runs in the browser. It creates the private key, public key, and CSR locally on the client device. No key material is sent to a server.

By default it generates:

- PEM-encoded PKCS#10 CSR
- PEM-encoded PKCS#8 private key
- PEM-encoded public key

Advanced export options are available for DER, encrypted PKCS#8, and traditional RSA/EC private key formats.

## Tech Stack

- Vite
- React
- TypeScript
- Tailwind CSS

## Run Locally

```bash
npm install
npm run dev
```

Open the URL printed by Vite, usually:

```text
http://localhost:5173
```

## Build

```bash
npm run build
npm run preview
```

## Backend

The current frontend is static-first. Tools such as DNS lookup, HTTP headers, TLS certificate inspection, RDAP/WHOIS, redirects, and SMTP banner checks need a backend because browsers cannot directly perform those network operations.