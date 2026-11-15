# Secure Password Vault Platform

This is a local demonstration project built around Vaultwarden, FastAPI, React, and Nginx. It is not production-ready.

## Repository Structure

```
SecureByDesign/
    .gitignore
    README.md
    secure-password-vault/
        .env.example
        docker-compose.yml
        backend/
            main.py
            schemas.py
            dependencies.py
            vaultwarden_client.py
            analytics.py
            auth_module.py
            breach_detection.py
            login_monitor.py
            password_strength.py
            password_generator.py
            attack_simulator.py
            backup_manager.py
            Dockerfile
        frontend/
            package.json
            webpack.config.js
            public/
            src/
        vaultwarden/
            vw-data/          # local runtime data; ignored by Git
            config/
        nginx/
            nginx.conf
            certs/            # local cert/key files; ignored by Git
        scripts/
            setup.sh
            full_setup.sh
            run.sh
            run_all.sh
            install_frontend.sh
            stop_all.sh
            demo.sh
            restore_backup.sh
            test.sh
            test.ps1
        docs/
            architecture.md
            setup_guide.md
            security_model.md
            api.md
            demo_workflow.md
            logging.md
            repo_structure.md
            test_data.md
            threat_model.md
            ai_assisted_development.md
```

---

All components run locally using Docker. See documentation for setup and usage.

## Backend Module Ownership

- `main.py` creates the FastAPI app, configures middleware, and registers routers.
- `schemas.py` contains request models shared by feature modules.
- `dependencies.py` contains shared bearer-token extraction.
- `vaultwarden_client.py` handles backend-to-Vaultwarden HTTP communication.
- `auth_module.py` handles Vaultwarden token login and authenticated sync/cipher proxy routes.
- `password_strength.py` analyzes individual passwords and batches of decrypted vault entries.
- `breach_detection.py` owns the local known-password check and `/check-breach` route.
- `login_monitor.py` detects suspicious login submissions and records demo events in memory.
- `analytics.py` computes the current vault metadata score.
- `password_generator.py` generates random passwords and passphrases.
- `attack_simulator.py` estimates attack effort without running real password-cracking attempts.
- `backup_manager.py` owns the backup route; it currently returns HTTP 501 because real encrypted backup/restore is not implemented.
