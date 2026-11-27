# VPNTC — VPN Temporal Control

> 🇺🇸 **English** | 🇧🇷 **[Versão em Português abaixo](#pt-br)**

---

## 🇺🇸 English

A containerized web application for managing, auditing, and automatically expiring temporary VPN access integrated with **Active Directory (LDAPS)** and **FortiAnalyzer**, designed to eliminate auxiliary duration groups (`30d`, `60d`, `90d`) and standalone scheduled scripts.

### 🎯 Objective

Centralize VPN access provisioning, monitoring, and renewal workflows for IT support teams (Tier 1 / Tier 2 / Tier 3), ensuring:
- **Dynamic VPN profiles (zero hardcoded groups):** Manage any number of Active Directory VPN groups directly from the web `/config` panel via live AD group search, without touching code or environment files.
- **Automated expiration:** A background scheduler periodically checks expiration timestamps and automatically removes expired users from their respective AD groups.
- **Flexible durations & one-click renewal:** Support standard (`30d`, `60d`, `90d`) or custom day durations (`1` to `3650` days), plus instant renewal of expired/revoked access linked to a support ticket.
- **FortiAnalyzer telemetry:** Track online status, last connection timestamp, and total connected duration for active VPN users via FortiAnalyzer JSON-RPC API.
- **Traceability and Auditing:** Full audit trail of grants, renewals, manual revocations, automatic expirations, and configuration changes, identifying the responsible analyst via authentication headers (`Remote-User`).

### 🛠️ Tech Stack

- **Backend:** Python 3.12, Flask, Flask-SQLAlchemy, Gunicorn, Cryptography (`Fernet`)
- **AD Integration:** `ldap3` (LDAPS / port 636)
- **Telemetry Integration:** FortiAnalyzer JSON-RPC API (`/logview`)
- **Task Scheduling:** `APScheduler` (BackgroundScheduler running on a single worker)
- **Database:** SQLite (persisted via Docker volume)
- **Frontend:** HTML5, Bootstrap 5 (Dark Theme), Vanilla JavaScript (Fetch API)
- **Infrastructure & Security:** Docker, Docker Compose, Traefik Reverse Proxy + Authelia (ForwardAuth)

### 📁 Project Structure

    VPNTC/
    ├── app/
    │   ├── __init__.py          # App factory, SQLite initialization, and Scheduler setup
    │   ├── models.py            # SystemSetting, VpnProfile, VpnAccess, and AuditLog models
    │   ├── ldap_service.py      # Dynamic AD user/group lookup and membership management
    │   ├── faz_service.py       # FortiAnalyzer JSON-RPC client for VPN usage telemetry
    │   ├── scheduler.py         # Periodic background job for expiration and FAZ sync
    │   ├── routes.py            # Web routes, AD search API, /config panel, RBAC, and actions
    │   └── templates/           # Web UI templates (base.html, dashboard.html, logs.html, config.html)
    ├── data/                    # Persistent SQLite volume directory (git-ignored)
    ├── .env.example             # Minimal bootstrap environment variables template
    ├── .gitignore               # Git exclusion rules for secrets and local data
    ├── Dockerfile               # Python slim container image running Gunicorn
    ├── docker-compose.yml       # Service orchestration with Traefik + Authelia labels
    └── requirements.txt         # Python dependencies

### 🚀 Getting Started (Docker)

1. **Clone the repository:**
   `git clone https://github.com/94bits-amazon/VPNTC.git && cd VPNTC`

2. **Configure bootstrap environment variables:**
   `cp .env.example .env`
   Set `SECRET_KEY` (used to sign sessions and encrypt stored credentials in SQLite). Other settings (AD, VPN groups, FortiAnalyzer API, and Admin RBAC groups) can be configured directly in the web `/config` panel.

3. **Start the container:**
   Ensure the external reverse proxy network (`proxy`) exists, update the host rule in `docker-compose.yml`, and run:
   `docker compose up -d --build`

### 🔐 Security

- **Edge Authentication & RBAC:** The container exposes no host ports directly, receiving traffic exclusively over the internal reverse proxy network protected by **Authelia** (`Remote-User` and `Remote-Groups` headers).
- **Encrypted Credentials at Rest:** AD bind passwords and FortiAnalyzer API tokens configured via the web UI are encrypted in SQLite using `Fernet` symmetric encryption derived from `SECRET_KEY`.
- **Principle of Least Privilege:** Delegate only user read permissions on the target user OU and `member` attribute modification rights on the target VPN groups to the AD service account.

### 📌 Development Status

- [x] Base project structure and Docker configuration (`Dockerfile` and `docker-compose.yml`)
- [x] Dynamic database models with encrypted settings (`SystemSetting`, `VpnProfile`, `VpnAccess`, `AuditLog`)
- [x] Dynamic LDAPS integration service (`search_users`, `search_groups`, `add_user_to_group`, `remove_user_from_group`)
- [x] FortiAnalyzer JSON-RPC telemetry service (`faz_service.py`)
- [x] Automated expiration and telemetry sync scheduler (`scheduler.py`)
- [x] Application factory (`__init__.py`) and routes (`routes.py`) with `/config`, RBAC, and custom durations
- [x] Complete Web UI templates (`base.html`, `dashboard.html`, `logs.html`, `config.html`)
- [ ] Staging tests with production Active Directory, FortiAnalyzer, and Authelia

---

<a id="pt-br"></a>
## 🇧🇷 VPNTC — Controle Temporal de VPN (PT-BR)

Sistema web containerizado para gestão, auditoria e expiração automática de acessos temporários de VPN integrados ao **Active Directory (LDAPS)** e **FortiAnalyzer**, projetado para substituir grupos auxiliares de prazo (`30d`, `60d`, `90d`) e scripts agendados avulsos.

### 🎯 Objetivo

Centralizar a operação de concessão, monitoramento e renovação de acesso VPN para equipes de suporte (N1/N2/N3), garantindo:
- **Perfis de VPN dinâmicos (sem hardcode):** cadastre e gerencie quantos grupos do AD desejar diretamente pela tela `/config` com busca em tempo real no AD, sem alterar código ou `.env`.
- **Expiração automática:** job em segundo plano verifica periodicamente os prazos e remove automaticamente do grupo no AD os usuários vencidos.
- **Prazos flexíveis e renovação em 1 clique:** suporte a períodos padrão (`30d`, `60d`, `90d`) ou prazo personalizado em dias (`1` a `3650`), além de reativação imediata de acessos vencidos vinculada a um chamado.
- **Telemetria via FortiAnalyzer:** consulta status online/offline, última conexão e tempo total conectado dos usuários ativos via API JSON-RPC do FortiAnalyzer.
- **Rastreabilidade e Auditoria:** registro completo de concessões, renovações, revogações manuais, expirações automáticas e alterações de configuração, identificando o analista responsável via headers de autenticação (`Remote-User`).

### 🛠️ Stack Tecnológica

- **Backend:** Python 3.12, Flask, Flask-SQLAlchemy, Gunicorn, Cryptography (`Fernet`)
- **Integração AD:** `ldap3` (LDAPS / porta 636)
- **Telemetria:** API JSON-RPC do FortiAnalyzer (`/logview`)
- **Agendamento:** `APScheduler` (BackgroundScheduler em worker único)
- **Banco de Dados:** SQLite (persistido em volume Docker)
- **Frontend:** HTML5, Bootstrap 5 (Dark Theme), JavaScript (Vanilla Fetch API)
- **Infraestrutura & Segurança:** Docker, Docker Compose, Traefik Reverse Proxy + Authelia (ForwardAuth)

### 📁 Estrutura do Projeto

    VPNTC/
    ├── app/
    │   ├── __init__.py          # Inicialização da aplicação, SQLite e Scheduler
    │   ├── models.py            # Modelos SystemSetting, VpnProfile, VpnAccess e AuditLog
    │   ├── ldap_service.py      # Consulta dinâmica de usuários/grupos e gestão de membros no AD
    │   ├── faz_service.py       # Cliente JSON-RPC do FortiAnalyzer para telemetria de uso
    │   ├── scheduler.py         # Rotina automática de expiração e sincronização com FAZ
    │   ├── routes.py            # Rotas web, API de busca AD, painel /config, RBAC e ações
    │   └── templates/           # Interface web (base.html, dashboard.html, logs.html, config.html)
    ├── data/                    # Volume persistente do banco SQLite (ignorado no Git)
    ├── .env.example             # Modelo mínimo de variáveis de ambiente
    ├── .gitignore               # Regras de exclusão de arquivos sensíveis e locais
    ├── Dockerfile               # Build da imagem Python slim com Gunicorn
    ├── docker-compose.yml       # Orquestração com labels Traefik + Authelia
    └── requirements.txt         # Dependências Python

### 🚀 Como Executar (Docker)

1. **Clonar o repositório:**
   `git clone https://github.com/94bits-amazon/VPNTC.git && cd VPNTC`

2. **Configurar variáveis iniciais:**
   `cp .env.example .env`
   Defina a `SECRET_KEY` (usada para assinar sessões e criptografar credenciais salvas no SQLite). Os demais parâmetros (AD, grupos VPN, API do FortiAnalyzer e grupos Admin RBAC) podem ser configurados diretamente na tela `/config`.

3. **Subir o container:**
   Certifique-se de que a rede externa do proxy reverso (`proxy`) existe, ajuste o domínio no `docker-compose.yml` e execute:
   `docker compose up -d --build`

### 🔐 Segurança

- **Autenticação na Borda e RBAC:** A aplicação não expõe portas diretamente no host, recebendo tráfego exclusivamente via rede interna do reverse proxy protegido pelo **Authelia** (`Remote-User` e `Remote-Groups`).
- **Credenciais Criptografadas em Repouso:** Senhas de bind LDAP e API Tokens do FortiAnalyzer salvos pela interface web são criptografados no SQLite usando criptografia simétrica `Fernet` derivada da `SECRET_KEY`.
- **Princípio do Menor Privilégio:** Recomenda-se delegar à conta de serviço do AD apenas permissão de leitura na OU de usuários e modificação de membros nos grupos específicos de VPN.

### 📌 Status do Desenvolvimento

- [x] Estrutura base do projeto e configuração Docker (`Dockerfile` e `docker-compose.yml`)
- [x] Modelos de dados dinâmicos com configurações criptografadas (`SystemSetting`, `VpnProfile`, `VpnAccess`, `AuditLog`)
- [x] Serviço de integração LDAPS dinâmico (`search_users`, `search_groups`, `add_user_to_group`, `remove_user_from_group`)
- [x] Serviço de telemetria FortiAnalyzer JSON-RPC (`faz_service.py`)
- [x] Agendador automático de expiração e sincronização de telemetria (`scheduler.py`)
- [x] Inicialização da aplicação (`__init__.py`) e rotas (`routes.py`) com `/config`, RBAC e prazos customizados
- [x] Templates HTML completos da interface web (`base.html`, `dashboard.html`, `logs.html`, `config.html`)
- [ ] Testes em ambiente de homologação com Active Directory, FortiAnalyzer e Authelia