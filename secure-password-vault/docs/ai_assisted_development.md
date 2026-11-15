# AI-Assisted Development and Project Contribution

## Purpose

SecureByDesign was developed through a human-led, AI-assisted workflow. The project owner set the goals, made product and scope decisions, ran the application, reviewed results, and decided which changes were appropriate. An AI coding assistant supported implementation, troubleshooting, test creation, and documentation. AI output was treated as a draft to inspect and verify, not as evidence that a feature worked.

## Project Owner's Contribution

The project owner:

- Defined the project goal: combine login and account-detail management with password-security analysis.
- Chose the desired local architecture around Vaultwarden, a dashboard, an analysis API, a reverse proxy, and Docker Compose.
- Identified the expected user workflow and the capabilities to demonstrate, including password analysis, reuse findings, generation, login alerts, and attack estimates.
- Ran Docker, API, and test commands in the target Windows/Docker environment and shared actual errors and responses for diagnosis.
- Reviewed whether the code organization matched the intended project structure and requested that security features be separated into focused backend modules.
- Set scope constraints when changes risked disrupting the demo, including preserving the existing vault, token defaults, service ports, and demo behavior.
- Reviewed project descriptions and requested accurate, audience-appropriate README and presentation material.

The owner remained responsible for project direction, accepting or rejecting changes, testing in the intended environment, and deciding what was ready to demonstrate.

## AI Assistant's Contribution

The AI assistant was used as a development aid to:

- Scaffold and refine FastAPI feature modules and shared request models.
- Help separate route and analysis responsibilities instead of keeping all behavior in one application file.
- Draft focused tests for API behavior, password analysis, generation, alert heuristics, attack estimates, and mocked Vaultwarden requests.
- Analyze Docker, HTTP, Vaultwarden, and build errors using the supplied command output and current configuration.
- Suggest and verify documentation, setup scripts, test runners, and repository ignore rules.
- Produce draft user-facing explanations and project presentation material.

The assistant did not independently decide the product's goals, validate the project with real customer data, or certify it as secure or production-ready.

## Development Approach

### 1. Define the product and demo

The work began with the desired outcome: a local password-vault experience with a security dashboard. The project owner identified the important demo journey and asked that the system remain runnable locally without paid services.

### 2. Establish the service boundaries

The project was organized around Vaultwarden for vault storage, a React dashboard for the user experience, FastAPI modules for analysis, and Nginx/Docker Compose for local routing and deployment. During review, the backend was reorganized so password analysis, breach-list checks, login alerts, analytics, generation, attack estimates, and authentication had distinct ownership.

### 3. Implement incrementally

Features were built and refined in small slices. Examples include the login and vault-sync flow, per-item password findings, a local password generator, and a non-executing attack-estimation model. When expected behavior did not match observed behavior, the owner supplied browser or container output so the relevant code path could be examined.

### 4. Verify against actual behavior

The project was checked using automated backend tests, frontend production builds, Docker Compose validation, shell syntax checks, and live service health checks. Vaultwarden calls in unit tests were mocked so tests did not need a real account or password. A live API health check and a sample attack-estimate request were also used to verify deployed routes.

### 5. Correct inaccurate assumptions

Review identified places where drafts or earlier descriptions overstated the implementation. For example, the backup endpoint was made explicit as HTTP 501 rather than described as a completed encrypted backup. The breach check was documented as a small local demo list, attack scenarios as estimates rather than executed attacks, and login alerts as a simple heuristic. The owner also requested that cleanup and troubleshooting preserve the demo configuration and local Vaultwarden data.

## Verification Evidence

- The backend test suite has passed with 36 tests in the local development environment.
- The frontend production build completed; webpack reported a bundle-size advisory that remains a performance follow-up.
- Docker Compose configuration validation passed.
- A clean backend image build succeeded after the package-install network issue was diagnosed and addressed.
- The complete local stack started, Vaultwarden reported healthy, and the FastAPI health route returned an `ok` response.
- A live HTTPS request to the attack-estimation route returned a structured estimate and model assumptions.

These checks demonstrate functional behavior in the local demo environment. They are not a penetration test, security certification, production-readiness review, or evidence of real-world risk reduction.

## Lessons from Using an AI Assistant

- Give the assistant concrete context: source files, command output, environment, and the expected behavior.
- Ask it to follow the data path and module ownership instead of accepting a plausible-sounding explanation.
- Validate proposed changes with focused tests and the real build/runtime environment.
- Keep product decisions and demo-critical constraints under human control.
- Review generated documentation for unsupported claims, especially around encryption, breach intelligence, persistence, backups, and security guarantees.
- Never provide real account passwords, access tokens, private keys, or production vault data to an AI tool or demo analysis service.

## Current Scope and Next Steps

SecureByDesign is a local academic demonstration. It currently has a small local common-password list, in-memory login-alert events, illustrative attack estimates, no implemented backup/restore, and a PostgreSQL service that is not connected to the backend. The dashboard sends decrypted login fields to the analysis API, so the demo should use disposable test data.

Potential future work includes privacy-preserving analysis, a broader breach-intelligence source, persistent security events, real encrypted backup/restore, stronger deployment secrets and TLS, and browser-level integration testing. These are roadmap items, not completed features.

## Suggested Acknowledgment

“I used an AI coding assistant to help scaffold and refactor modules, draft tests and documentation, and investigate errors. I provided the requirements, made the design and scope decisions, ran the application and tests, reviewed the generated changes, and corrected the project based on observed behavior. AI-generated output was not treated as verified until checked.”