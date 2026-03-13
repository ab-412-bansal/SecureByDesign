
# SecureByDesign

A modern, open-source password management and security intelligence platform designed for individuals and teams. SecureByDesign combines a self-hosted Bitwarden-compatible vault (Vaultwarden), advanced password analysis, breach detection, and a user-friendly dashboard to help you manage, audit, and protect your credentials with confidence.

---

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [How It Works](#how-it-works)
- [Benefits](#benefits)
- [Technology Stack](#technology-stack)
- [Setup & Usage](#setup--usage)
- [Security Model](#security-model)
- [Licenses](#licenses)
- [Contributing](#contributing)
- [Acknowledgments](#acknowledgments)

---

## Overview
SecureByDesign is a full-stack solution for secure password storage, analysis, and breach monitoring. It leverages Vaultwarden (a Bitwarden-compatible server) for encrypted vault storage, a FastAPI backend for security intelligence, and a React-based frontend dashboard for seamless user experience. The platform is containerized for easy deployment and includes advanced tools for password strength analysis, breach detection, and attack simulation.

---

## Features
- **Self-hosted Password Vault**: Store and manage credentials using Vaultwarden, compatible with Bitwarden clients.
- **Security Intelligence API**: Analyze password strength, detect breaches, and simulate attacks via a robust FastAPI backend.
- **Real-time Dashboard**: Visualize vault health, password risks, and security events in a modern React dashboard.
- **Breach Detection**: Check passwords and emails against known breach lists.
- **Password Strength Analysis**: Entropy, pattern, and risk scoring for all vault items.
- **Attack Simulation**: Test password resilience against common attack vectors.
- **Backup & Restore**: Automated vault backup and restore tools.
- **Role-based Access**: Secure authentication and session management.
- **Audit Logging**: Track login attempts and security events.
- **Containerized Deployment**: Easy setup with Docker Compose and Nginx reverse proxy.

---

## Architecture
- **Vaultwarden**: Bitwarden-compatible server for encrypted credential storage.
- **Backend (FastAPI)**: Security analysis, breach detection, and API endpoints.
- **Frontend (React)**: Security dashboard and user interface.
- **Nginx**: SSL termination and reverse proxy for secure API and frontend access.
- **PostgreSQL**: Database for Vaultwarden data.
- **Docker Compose**: Orchestrates all services for local or cloud deployment.

See [docs/architecture_diagram.md](docs/architecture_diagram.md) for a detailed diagram.

---

## How It Works
1. **User Registration & Login**: Users register and log in via the frontend, which communicates with the backend and Vaultwarden.
2. **Password Storage**: Credentials are encrypted client-side and stored in Vaultwarden.
3. **Security Analysis**: The backend analyzes passwords for strength, common patterns, and breach status.
4. **Dashboard Insights**: Users view vault health, risk scores, and breach alerts in real time.
5. **Attack Simulation**: Users can simulate brute-force or dictionary attacks on their passwords.
6. **Backup & Restore**: Admins can schedule or trigger secure vault backups.

---

## Benefits
- **Data Sovereignty**: All data is self-hosted—no third-party cloud required.
- **Advanced Security**: Modern cryptography, breach detection, and attack simulation.
- **Transparency**: Open-source codebase and auditable security model.
- **User-friendly**: Intuitive dashboard and Bitwarden client compatibility.
- **Scalable**: Suitable for individuals, teams, and organizations.

---

## Technology Stack
- **Vaultwarden** (Bitwarden-compatible server)
- **FastAPI** (Python backend)
- **React** (Frontend dashboard)
- **Nginx** (SSL reverse proxy)
- **PostgreSQL** (Database)
- **Docker & Docker Compose** (Container orchestration)
- **Node.js** (Frontend runtime)

---


## Setup & Usage
1. **Clone the repository:**
	```sh
	git clone https://github.com/your-org/SecureByDesign.git
	cd SecureByDesign
	```
2. **Configure SSL certificates:**
	Place your SSL certs in `nginx/certs/` as `cert.pem` and `key.pem`.
3. **Start all services:**
	```sh
	docker-compose up --build -d
	```
4. **Access the dashboard:**
	- Frontend: https://localhost/
	- API docs: https://localhost/api/docs
	- Vaultwarden: https://localhost:9443/

See [docs/setup_guide.md](docs/setup_guide.md) for detailed instructions.

---

## Security Model
- **End-to-end Encryption**: All vault data is encrypted client-side before storage.
- **PBKDF2 & HKDF**: Strong key derivation and stretching for master passwords.
- **Zero Knowledge**: Server never sees or stores plain user passwords.
- **Breach Monitoring**: Passwords and emails checked against breach lists.
- **Audit Logging**: Security events and login attempts are tracked.

See [docs/security_model.md](docs/security_model.md) and [docs/threat_model.md](docs/threat_model.md) for more details.

---

## Licenses
- **Vaultwarden**: GPL-3.0 License
- **SecureByDesign (this repo)**: MIT License (see [LICENSE](LICENSE))
- **Frontend dependencies**: See `frontend/package.json` for details

---

## Contributing
Contributions are welcome! Please see [docs/repo_structure.md](docs/repo_structure.md) and open an issue or pull request.

---

## Acknowledgments
- [Vaultwarden](https://github.com/dani-garcia/vaultwarden)
- [Bitwarden](https://bitwarden.com/)
- [FastAPI](https://fastapi.tiangolo.com/)
- [React](https://react.dev/)
- [Docker](https://www.docker.com/)

---

For more documentation, see the [docs/](docs/) folder.
