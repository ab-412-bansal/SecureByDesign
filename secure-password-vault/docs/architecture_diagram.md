# System Architecture Diagram (Mermaid)

```mermaid
graph TD
    A[Client Layer (Web UI, Bitwarden Extension)] -->|HTTPS| B(Nginx Reverse Proxy)
    B --> C(Vaultwarden Server)
    B --> D(Backend Security API)
    D --> E[Security Intelligence Modules]
    E --> E1[Password Strength Analyzer]
    E --> E2[Breach Detection]
    E --> E3[Suspicious Login Detection]
    E --> E4[Analytics Dashboard]
    E --> E5[Password Generator]
    E --> E6[Attack Simulator]
    E --> E7[Encrypted Backup]
    C --> F[(Database)]
    D --> F
```

---

*All services run locally in Docker containers.*
