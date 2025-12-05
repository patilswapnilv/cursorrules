# Cursor AI Project Rules for Modern Development

[![Cursor Rules Tests](https://github.com/patilswapnilv/cursorrules/actions/workflows/test.yml/badge.svg)](https://github.com/patilswapnilv/cursorrules/actions/workflows/test.yml)

## 📌 About This Repository
This repository contains a **comprehensive set of Cursor AI rules** designed to **enhance efficiency, enforce coding standards, and automate best practices** across **multiple programming languages and frameworks**, including **PHP/Drupal, JavaScript/React/Vue, Python, WordPress, TypeScript/Node.js, and DevOps technologies**, with a **strong focus on security** following **OWASP Top 10** guidelines.

This project extends the [original cursor-rules repository](https://github.com/ivangrynenko/cursor-rules) by [Ivan Grynenko](https://github.com/ivangrynenko) to support a **full polyglot stack**, providing specialized rules for modern development workflows across diverse technology ecosystems.

These rules help **Cursor AI** assist developers by:
- Enforcing coding standards and best practices
- Ensuring tests and documentation remain up to date
- Detecting inefficiencies in AI query usage and improving response quality
- Providing automated suggestions for commit messages, dependencies, and performance optimisations

---

## 🚀 Who Is This For?
This repository is ideal for:
- **PHP & Drupal developers** following Drupal coding standards and security best practices
- **WordPress developers** building plugins and themes with modern PHP practices
- **TypeScript/Node.js developers** working with NestJS, Express, Fastify, and modern server-side frameworks
- **Frontend developers** working with JavaScript, React, Next.js, Vue, Tailwind, and other modern frameworks
- **Python developers** building data pipelines, ML/AI applications, and ETL processes
- **Database developers** working with SQL, Prisma, TimescaleDB, pgvector, and Neo4j
- **DevOps engineers** working with Docker, Kubernetes, Terraform, Helm, and CI/CD workflows
- **Security-conscious developers** implementing OWASP Top 10 protections
- **Software teams** looking for a structured, automated workflow with comprehensive rule sets
- **Open-source contributors** who want standardized development and security practices

## 🌐 Supported Languages & Contexts

This repository provides specialized rules for a comprehensive polyglot stack:

- **TypeScript / Node.js 20.x+ / NestJS / Express / Fastify**  
  Server-side TypeScript development with framework-specific patterns, type safety, async/await patterns, and validation

- **JavaScript (scripts, tooling)**  
  Build scripts, utilities, and Node.js ecosystem packages

- **WordPress / PHP 7.4+**  
  Plugin and theme development, WordPress core APIs and hooks, security best practices, performance optimization

- **Python 3.11+ (ETL, data pipelines, ML/AI tasks)**  
  Data processing and ETL pipelines, machine learning and AI model development, type hints, logging, exception handling

- **SQL (PostgreSQL, TimescaleDB, pgvector), graph DB queries (Cypher for Neo4j)**  
  Relational database operations, time-series data, vector embeddings, graph database queries

- **Frontend: React / Next.js / UI + data-visualization (D3, MapLibre, etc.)**  
  React component patterns, Next.js App Router (13+), data visualization libraries, styling (Tailwind CSS, CSS-in-JS)

- **Infra & config: YAML / JSON / Docker / Kubernetes / Helm / Terraform / Cloud-provider manifests**  
  Infrastructure as Code (IaC), container orchestration, cloud provider configurations, secrets management

- **Job queues: Redis, BullMQ / RabbitMQ / message-queue workflows**  
  Background job processing, message broker patterns, idempotency and retry strategies

- **CI/CD / DevOps: GitHub Actions, Docker Compose, Kubernetes, Terraform**  
  Continuous integration and deployment, containerization and orchestration, infrastructure automation

- **ML / vector-DB / embeddings / model-serving context**  
  Machine learning model development, vector database operations, embedding generation and similarity search

---

## 📥 Installation

### Interactive Installation (Recommended)

For a fully interactive installation with prompts:

```bash
# Step 1: Download the installer
curl -s https://raw.githubusercontent.com/patilswapnilv/cursorrules/main/install.php -o install.php

# Step 2: Run the installer interactively
php install.php
```

This two-step process ensures you get the interactive experience with:
- Prompts to choose which rule sets to install (Core, Web Stack, Python, or All)
- Option to remove the installer file after installation (defaults to yes)

### Quick Non-Interactive Installation

For a quick installation without prompts (installs core rules only):

```bash
curl -s https://raw.githubusercontent.com/patilswapnilv/cursorrules/main/install.php | php
```

or install rules by tag expression
```bash
curl -s https://raw.githubusercontent.com/patilswapnilv/cursorrules/main/install.php | php -- --tags "language:javascript category:security"
```

⚠️ **Note**: When using the curl piping method above, interactive mode is **not possible** because STDIN is already being used for the script input. The installer will automatically default to installing core rules only.

### Installation with Specific Options

To install with specific options and bypass the interactive mode:

```bash
curl -s https://raw.githubusercontent.com/patilswapnilv/cursorrules/main/install.php | php -- [options]
```

For example, to install all rules:

```bash
curl -s https://raw.githubusercontent.com/patilswapnilv/cursorrules/main/install.php | php -- --all
```

### Installation Options

The installer supports the following options:
- `--core`: Install core rules only
- `--web-stack` or `--ws`: Install web stack rules (includes core rules)
- `--python`: Install Python rules (includes core rules)
- `--all`: Install all rules
- `--yes` or `-y`: Automatically answer yes to all prompts
- `--destination=DIR`: Install to a custom directory (default: .cursor/rules)
- `--debug`: Enable detailed debug output for troubleshooting installation issues
- `--ignore-files <opt>`: Control installation of .cursorignore files (yes, no, ask), defaults to yes
- `--help` or `-h`: Show help message

### .cursorignore Files

The installer can automatically add recommended `.cursorignore` and `.cursorindexingignore` files to your project. These files tell Cursor AI which files and directories to exclude from processing, which helps to:

- **Improve performance** by skipping large generated files, vendor directories, and node_modules
- **Reduce noise** in AI responses by focusing only on relevant project files
- **Prevent unnecessary context** from third-party code being included in AI prompts

The `.cursorignore` file ensures files are not indexed by Cursor and they are not read by Cursor or sent to the models for processing. This is a good setting for files that may contain secrets or other information you'd prefer to keep private. The `.cursorindexingignore` file is just for indexing and is there mainly for performance reasons.

By default, the installer will add these files (controlled by the `--ignore-files` option). You can:
- Set to `yes` (default): Always install ignore files
- Set to `no`: Never install ignore files
- Set to `ask`: Prompt during installation

If you need to modify the ignore patterns, you can edit the `.cursorignore` files manually after installation.

### Troubleshooting Installation

If you encounter issues during installation, try running the installer with the debug option:

```bash
php install.php --debug
```

This will provide detailed information about what the installer is doing, which can help identify the source of any problems.

Common issues:
- If only core rules are installed when selecting other options, make sure your internet connection is working properly as the installer needs to download additional rules from GitHub.
- If you're behind a corporate firewall or proxy, you may need to configure PHP to use your proxy settings.

### Examples

Install core rules only:
```bash
curl -s https://raw.githubusercontent.com/patilswapnilv/cursorrules/main/install.php | php -- --core
```

Install web stack rules (includes core rules):
```bash
curl -s https://raw.githubusercontent.com/patilswapnilv/cursorrules/main/install.php | php -- --web-stack
# Or using the shorter alias
curl -s https://raw.githubusercontent.com/patilswapnilv/cursorrules/main/install.php | php -- --ws
```

Install all rules:
```bash
curl -s https://raw.githubusercontent.com/patilswapnilv/cursorrules/main/install.php | php -- --all
```

Install to a custom directory:
```bash
curl -s https://raw.githubusercontent.com/patilswapnilv/cursorrules/main/install.php | php -- --all --destination=my/custom/path
```

#### Tag-Based Selection

The installer now supports filtering rules by tags, allowing you to install only the rules relevant to your project:

```sh
# Install all JavaScript security rules
curl -s https://raw.githubusercontent.com/patilswapnilv/cursorrules/main/install.php | php -- --tags "language:javascript category:security"

# Install all OWASP Top 10 rules for PHP
curl -s https://raw.githubusercontent.com/patilswapnilv/cursorrules/main/install.php | php -- --tags "language:php standard:owasp-top10"

# Install all React-related rules
curl -s https://raw.githubusercontent.com/patilswapnilv/cursorrules/main/install.php | php -- --tags "framework:react"

# Install rules matching multiple criteria with OR logic
curl -s https://raw.githubusercontent.com/patilswapnilv/cursorrules/main/install.php | php -- --tags "language:javascript OR language:php"
```

Available tag presets:
- `web`: JavaScript, HTML, CSS, PHP
- `frontend`: JavaScript, HTML, CSS
- `drupal`: Drupal-specific rules
- `react`: React-specific rules
- `vue`: Vue-specific rules
- `python`: Python-specific rules
- `security`: Security-focused rules
- `owasp`: OWASP Top 10 rules
- `a11y`: Accessibility rules
- `php-security`: PHP security-focused rules
- `js-security`: JavaScript security-focused rules
- `python-security`: Python security-focused rules
- `drupal-security`: Drupal security-focused rules
- `php-owasp`: PHP OWASP Top 10 rules
- `js-owasp`: JavaScript OWASP Top 10 rules
- `python-owasp`: Python OWASP Top 10 rules
- `drupal-owasp`: Drupal OWASP Top 10 rules
- `wordpress`: WordPress-specific rules
- `typescript`: TypeScript-specific rules
- `nodejs`: TypeScript, NestJS, Express, Fastify rules
- `nextjs`: Next.js-specific rules
- `database`: Database and ORM rules (Prisma, SQL)
- `python-data`: Python data pipeline and ML/AI rules
- `infrastructure`: Infrastructure as Code rules
- `devops`: DevOps and CI/CD rules
- `messaging-queue`: Message queue and background job rules

See the [TAG_STANDARDS.md](TAG_STANDARDS.md) file for detailed information about the tagging system.

### Manual Installation

If you prefer to install manually:

1. Clone this repository:
   ```bash
   git clone https://github.com/patilswapnilv/cursorrules.git
   ```

2. Copy the rules to your project:
   ```bash
   mkdir -p /path/to/your/project/.cursor/rules
   cp -r cursorrules/.cursor/rules/* /path/to/your/project/.cursor/rules/
   ```

---

## 📜 Available Cursor Rules

Each rule is written in `.mdc` format and structured to enforce best practices in different aspects of development.

### Quick Reference: Polyglot Stack Rules

| Rule File | Applies To | Key Focus Areas |
|-----------|------------|-----------------|
| [`backend/typescript-node.mdc`](.cursor/rules/backend/typescript-node.mdc) | TypeScript, Node.js, NestJS, Express, Fastify | Type safety, async patterns, validation |
| [`database/sql-prisma.mdc`](.cursor/rules/database/sql-prisma.mdc) | SQL, Prisma, TimescaleDB, pgvector, Neo4j | Query safety, ORM patterns, migrations |
| [`backend/python-data.mdc`](.cursor/rules/backend/python-data.mdc) | Python 3.11+, data pipelines, ML/AI | Type hints, logging, exception handling |
| [`backend/data-pipeline-safety.mdc`](.cursor/rules/backend/data-pipeline-safety.mdc) | Python, ETL, data pipelines | Data pipeline safety, error handling, idempotency |
| [`devops/infra-devops.mdc`](.cursor/rules/devops/infra-devops.mdc) | Docker, K8s, Terraform, Helm | Security, configuration, secrets |
| [`frontend/frontend-react.mdc`](.cursor/rules/frontend/frontend-react.mdc) | React, Next.js, UI libraries | Components, state, styling, types |
| [`development/messaging-queue-patterns.mdc`](.cursor/rules/development/messaging-queue-patterns.mdc) | BullMQ, RabbitMQ, Redis | Idempotency, retries, error handling |
| [`wordpress/php-wordpress-standards.mdc`](.cursor/rules/wordpress/php-wordpress-standards.mdc) | WordPress, PHP 7.4+ | Security, hooks, performance, best practices |
| [`wordpress/php-wordpress-best-practices.mdc`](.cursor/rules/wordpress/php-wordpress-best-practices.mdc) | WordPress, PHP 7.4+ | PHP & WordPress Development Standards and Best Practices |
| [`wordpress/php-wordpress-development-standards.mdc`](.cursor/rules/wordpress/php-wordpress-development-standards.mdc) | WordPress, PHP 7.4+ | Standards for PHP and WordPress development |
| [`wordpress/wordpress-file-permissions.mdc`](.cursor/rules/wordpress/wordpress-file-permissions.mdc) | WordPress | WordPress file permissions security standards |
| [`database/wordpress-database-standards.mdc`](.cursor/rules/database/wordpress-database-standards.mdc) | WordPress | Database schema changes, migrations, and query optimisation for WordPress |

### Core Rules
| File Name | Purpose |
|-----------|---------|
| [`core/cursor-rules.mdc`](.cursor/rules/core/cursor-rules.mdc) | Defines standards for creating and organising Cursor rule files |
| [`core/git-commit-standards.mdc`](.cursor/rules/core/git-commit-standards.mdc) | Enforces structured Git commit messages with proper prefixes and formatting |
| [`core/github-actions-standards.mdc`](.cursor/rules/core/github-actions-standards.mdc) | Ensures GitHub Actions workflows follow best practices |
| [`core/improve-cursorrules-efficiency.mdc`](.cursor/rules/core/improve-cursorrules-efficiency.mdc) | Detects and optimises inefficient AI queries |
| [`core/pull-request-changelist-instructions.mdc`](.cursor/rules/core/pull-request-changelist-instructions.mdc) | Guidelines for creating consistent pull request changelists in markdown format with proper code block formatting |
| [`core/readme-maintenance-standards.mdc`](.cursor/rules/core/readme-maintenance-standards.mdc) | Ensures README documentation is comprehensive and up-to-date |
| [`core/testing-guidelines.mdc`](.cursor/rules/core/testing-guidelines.mdc) | Ensures proper testing practices and separation between test and production code |
| [`core/testing-data-pipelines.mdc`](.cursor/rules/core/testing-data-pipelines.mdc) | Data pipeline testing standards for ETL operations, data validation, and integration testing |
| [`core/testing-infrastructure.mdc`](.cursor/rules/core/testing-infrastructure.mdc) | Infrastructure testing standards for Terraform, Kubernetes, and Docker configurations |
| [`core/testing-python.mdc`](.cursor/rules/core/testing-python.mdc) | Python testing standards using pytest, unittest, and mocking patterns |
| [`core/testing-typescript.mdc`](.cursor/rules/core/testing-typescript.mdc) | TypeScript/JavaScript testing standards using Jest, Vitest, and testing-library |

### Web Development Rules

#### Frontend Development
| File Name | Purpose |
|-----------|---------|
| [`frontend/accessibility-standards.mdc`](.cursor/rules/frontend/accessibility-standards.mdc) | WCAG compliance and accessibility best practices |
| [`development/api-standards.mdc`](.cursor/rules/development/api-standards.mdc) | RESTful API design and documentation standards |
| [`development/build-optimization.mdc`](.cursor/rules/development/build-optimization.mdc) | Webpack/Vite configuration and build process optimisation |
| [`frontend/frontend-react.mdc`](.cursor/rules/frontend/frontend-react.mdc) | React/Next.js/UI standards for component structure, state management, styling, and data visualization |
| [`frontend/javascript-performance.mdc`](.cursor/rules/frontend/javascript-performance.mdc) | Best practices for optimising JavaScript performance |
| [`frontend/javascript-standards.mdc`](.cursor/rules/frontend/javascript-standards.mdc) | Standards for JavaScript development in Drupal |
| [`development/node-dependencies.mdc`](.cursor/rules/development/node-dependencies.mdc) | Node.js versioning and package management best practices |
| [`frontend/react-patterns.mdc`](.cursor/rules/frontend/react-patterns.mdc) | React component patterns and hooks usage guidelines |
| [`frontend/tailwind-standards.mdc`](.cursor/rules/frontend/tailwind-standards.mdc) | Tailwind CSS class organisation and best practices |
| [`frontend/vue-best-practices.mdc`](.cursor/rules/frontend/vue-best-practices.mdc) | Vue 3 and NuxtJS specific standards and optimisations |

#### Backend Development
| File Name | Purpose |
|-----------|---------|
| [`drupal/php-drupal-best-practices.mdc`](.cursor/rules/drupal/php-drupal-best-practices.mdc) | PHP & Drupal Development Standards and Best Practices |
| [`drupal/php-drupal-development-standards.mdc`](.cursor/rules/drupal/php-drupal-development-standards.mdc) | Standards for PHP and Drupal development |
| [`drupal/php-memory-optimisation.mdc`](.cursor/rules/drupal/php-memory-optimisation.mdc) | PHP memory optimisation standards and actionable checks |
| [`database/drupal-database-standards.mdc`](.cursor/rules/database/drupal-database-standards.mdc) | Database schema changes, migrations, and query optimisation |
| [`drupal/drupal-file-permissions.mdc`](.cursor/rules/drupal/drupal-file-permissions.mdc) | Drupal file permissions security standards |
| [`wordpress/php-wordpress-standards.mdc`](.cursor/rules/wordpress/php-wordpress-standards.mdc) | WordPress and PHP 7.4+ development standards for plugins, themes, hooks, security, performance, and WordPress coding standards |
| [`backend/typescript-node.mdc`](.cursor/rules/backend/typescript-node.mdc) | TypeScript/Node.js 20.x+/NestJS/Express/Fastify standards for type safety, async/await, validation, and module boundaries |
| [`database/sql-prisma.mdc`](.cursor/rules/database/sql-prisma.mdc) | SQL/Prisma/TimescaleDB/pgvector/Neo4j standards for database operations, migrations, and queries |
| [`database/database-migration-safety.mdc`](.cursor/rules/database/database-migration-safety.mdc) | Database migration safety standards for zero-downtime deployments, rollback procedures, and data validation |
| [`backend/python-data.mdc`](.cursor/rules/backend/python-data.mdc) | Python 3.11+ data pipeline/ML/ETL standards for type hints, logging, exception handling, and test coverage |
| [`backend/data-pipeline-safety.mdc`](.cursor/rules/backend/data-pipeline-safety.mdc) | Data pipeline safety standards for ETL operations, error handling, data validation, and idempotency |
| [`development/messaging-queue-patterns.mdc`](.cursor/rules/development/messaging-queue-patterns.mdc) | Job queue and message broker patterns for Redis/BullMQ/RabbitMQ with idempotency, retries, and error handling |

#### Security Rules
| File Name | Purpose |
|-----------|---------|
| [`security/drupal-authentication-failures.mdc`](.cursor/rules/security/drupal-authentication-failures.mdc) | Prevents authentication failures in Drupal |
| [`security/drupal-broken-access-control.mdc`](.cursor/rules/security/drupal-broken-access-control.mdc) | Prevents broken access control vulnerabilities in Drupal |
| [`security/drupal-cryptographic-failures.mdc`](.cursor/rules/security/drupal-cryptographic-failures.mdc) | Prevents cryptographic failures in Drupal applications |
| [`security/drupal-injection.mdc`](.cursor/rules/security/drupal-injection.mdc) | Prevents injection vulnerabilities in Drupal |
| [`security/drupal-insecure-design.mdc`](.cursor/rules/security/drupal-insecure-design.mdc) | Prevents insecure design patterns in Drupal |
| [`security/drupal-integrity-failures.mdc`](.cursor/rules/security/drupal-integrity-failures.mdc) | Prevents integrity failures in Drupal |
| [`security/drupal-logging-failures.mdc`](.cursor/rules/security/drupal-logging-failures.mdc) | Prevents logging failures in Drupal |
| [`security/drupal-security-misconfiguration.mdc`](.cursor/rules/security/drupal-security-misconfiguration.mdc) | Prevents security misconfigurations in Drupal |
| [`security/drupal-ssrf.mdc`](.cursor/rules/security/drupal-ssrf.mdc) | Prevents Server-Side Request Forgery in Drupal |
| [`security/drupal-vulnerable-components.mdc`](.cursor/rules/security/drupal-vulnerable-components.mdc) | Identifies and prevents vulnerable components in Drupal |
| [`security/javascript-broken-access-control.mdc`](.cursor/rules/security/javascript-broken-access-control.mdc) | Prevents broken access control vulnerabilities in JavaScript applications |
| [`security/javascript-cryptographic-failures.mdc`](.cursor/rules/security/javascript-cryptographic-failures.mdc) | Prevents cryptographic failures in JavaScript applications |
| [`security/javascript-injection.mdc`](.cursor/rules/security/javascript-injection.mdc) | Prevents injection vulnerabilities in JavaScript applications |
| [`security/javascript-insecure-design.mdc`](.cursor/rules/security/javascript-insecure-design.mdc) | Prevents insecure design patterns in JavaScript applications |
| [`security/javascript-security-misconfiguration.mdc`](.cursor/rules/security/javascript-security-misconfiguration.mdc) | Prevents security misconfigurations in JavaScript applications |
| [`security/javascript-vulnerable-outdated-components.mdc`](.cursor/rules/security/javascript-vulnerable-outdated-components.mdc) | Identifies and prevents vulnerable components in JavaScript applications |
| [`security/javascript-identification-authentication-failures.mdc`](.cursor/rules/security/javascript-identification-authentication-failures.mdc) | Prevents authentication failures in JavaScript applications |
| [`security/javascript-software-data-integrity-failures.mdc`](.cursor/rules/security/javascript-software-data-integrity-failures.mdc) | Prevents software and data integrity failures in JavaScript applications |
| [`security/javascript-security-logging-monitoring-failures.mdc`](.cursor/rules/security/javascript-security-logging-monitoring-failures.mdc) | Prevents logging and monitoring failures in JavaScript applications |
| [`security/javascript-server-side-request-forgery.mdc`](.cursor/rules/security/javascript-server-side-request-forgery.mdc) | Prevents Server-Side Request Forgery in JavaScript applications |
| [`security/wordpress-authentication-failures.mdc`](.cursor/rules/security/wordpress-authentication-failures.mdc) | Prevents authentication failures in WordPress |
| [`security/wordpress-broken-access-control.mdc`](.cursor/rules/security/wordpress-broken-access-control.mdc) | Prevents broken access control vulnerabilities in WordPress |
| [`security/wordpress-cryptographic-failures.mdc`](.cursor/rules/security/wordpress-cryptographic-failures.mdc) | Prevents cryptographic failures in WordPress applications |
| [`security/wordpress-injection.mdc`](.cursor/rules/security/wordpress-injection.mdc) | Prevents injection vulnerabilities in WordPress |
| [`security/wordpress-insecure-design.mdc`](.cursor/rules/security/wordpress-insecure-design.mdc) | Prevents insecure design patterns in WordPress |
| [`security/wordpress-integrity-failures.mdc`](.cursor/rules/security/wordpress-integrity-failures.mdc) | Prevents integrity failures in WordPress |
| [`security/wordpress-logging-failures.mdc`](.cursor/rules/security/wordpress-logging-failures.mdc) | Prevents logging failures in WordPress |
| [`security/wordpress-security-misconfiguration.mdc`](.cursor/rules/security/wordpress-security-misconfiguration.mdc) | Prevents security misconfigurations in WordPress |
| [`security/wordpress-ssrf.mdc`](.cursor/rules/security/wordpress-ssrf.mdc) | Prevents Server-Side Request Forgery in WordPress |
| [`security/wordpress-vulnerable-components.mdc`](.cursor/rules/security/wordpress-vulnerable-components.mdc) | Identifies and prevents vulnerable components in WordPress |
| [`security/security-practices.mdc`](.cursor/rules/security/security-practices.mdc) | Security best practices for PHP, JavaScript, and Drupal |
| [`security/secret-detection.mdc`](.cursor/rules/security/secret-detection.mdc) | Detects and prevents secrets from being committed to code |

#### DevOps & Infrastructure
| File Name | Purpose |
|-----------|---------|
| [`devops/docker-compose-standards.mdc`](.cursor/rules/devops/docker-compose-standards.mdc) | Docker Compose standards |
| [`devops/infra-devops.mdc`](.cursor/rules/devops/infra-devops.mdc) | Infrastructure as Code standards for Docker, Kubernetes, Terraform, Helm, cloud providers, and secrets management |
| [`devops/lagoon-docker-compose-standards.mdc`](.cursor/rules/devops/lagoon-docker-compose-standards.mdc) | Standards for Lagoon Docker Compose configuration |
| [`devops/lagoon-yml-standards.mdc`](.cursor/rules/devops/lagoon-yml-standards.mdc) | Standards for Lagoon configuration files and deployment workflows |
| [`devops/vortex-cicd-standards.mdc`](.cursor/rules/devops/vortex-cicd-standards.mdc) | Standards for Vortex CI/CD and Renovate configuration |
| [`devops/vortex-scaffold-standards.mdc`](.cursor/rules/devops/vortex-scaffold-standards.mdc) | Standards for Vortex/DrevOps scaffold usage and best practices |

#### Development Process
| File Name | Purpose |
|-----------|---------|
| [`development/code-generation-standards.mdc`](.cursor/rules/development/code-generation-standards.mdc) | Standards for code generation and implementation |
| [`development/debugging-standards.mdc`](.cursor/rules/development/debugging-standards.mdc) | Standards for debugging and error handling |
| [`development/generic_bash_style.mdc`](.cursor/rules/development/generic_bash_style.mdc) | Enforce general Bash scripting standards with enhanced logging |
| [`development/multi-agent-coordination.mdc`](.cursor/rules/development/multi-agent-coordination.mdc) | Multi-agent coordination and workflow standards |
| [`development/project-definition-template.mdc`](.cursor/rules/development/project-definition-template.mdc) | Template for defining project context |
| [`development/tests-documentation-maintenance.mdc`](.cursor/rules/development/tests-documentation-maintenance.mdc) | Require tests for new functionality and enforce documentation updates |
| [`development/third-party-integration.mdc`](.cursor/rules/development/third-party-integration.mdc) | Standards for integrating external services |
| [`development/observability-standards.mdc`](.cursor/rules/development/observability-standards.mdc) | Observability standards for logging, metrics, tracing, and monitoring in polyglot systems |
| [`development/confluence-editing-standards.mdc`](.cursor/rules/development/confluence-editing-standards.mdc) | Standards for editing Confluence documentation |
| [`development/new-pull-request.mdc`](.cursor/rules/development/new-pull-request.mdc) | Use this rule when requested to review a pull request |
| [`development/behat-steps.mdc`](.cursor/rules/development/behat-steps.mdc) | Documentation for available Behat testing steps in Drupal projects |
| [`development/behat-ai-guide.mdc`](.cursor/rules/development/behat-ai-guide.mdc) | AI assistant guide for writing Behat tests using drevops/behat-steps package |

### Python Rules
| File Name | Purpose |
|-----------|---------|
| [`security/python-authentication-failures.mdc`](.cursor/rules/security/python-authentication-failures.mdc) | Prevents authentication failures in Python |
| [`security/python-broken-access-control.mdc`](.cursor/rules/security/python-broken-access-control.mdc) | Prevents broken access control vulnerabilities in Python |
| [`security/python-cryptographic-failures.mdc`](.cursor/rules/security/python-cryptographic-failures.mdc) | Prevents cryptographic failures in Python applications |
| [`backend/python-data.mdc`](.cursor/rules/backend/python-data.mdc) | Python 3.11+ data pipeline/ML/ETL standards for type hints, logging, exception handling, and test coverage |
| [`security/python-injection.mdc`](.cursor/rules/security/python-injection.mdc) | Prevents injection vulnerabilities in Python |
| [`security/python-insecure-design.mdc`](.cursor/rules/security/python-insecure-design.mdc) | Prevents insecure design patterns in Python |
| [`security/python-integrity-failures.mdc`](.cursor/rules/security/python-integrity-failures.mdc) | Prevents integrity failures in Python |
| [`security/python-logging-monitoring-failures.mdc`](.cursor/rules/security/python-logging-monitoring-failures.mdc) | Prevents logging and monitoring failures in Python |
| [`security/python-security-misconfiguration.mdc`](.cursor/rules/security/python-security-misconfiguration.mdc) | Prevents security misconfigurations in Python |
| [`security/python-ssrf.mdc`](.cursor/rules/security/python-ssrf.mdc) | Prevents Server-Side Request Forgery in Python |
| [`security/python-vulnerable-outdated-components.mdc`](.cursor/rules/security/python-vulnerable-outdated-components.mdc) | Identifies and prevents vulnerable components in Python |

---

## 🔧 Usage

### In Cursor AI

Once installed, Cursor AI will automatically use these rules when working with your codebase. The rules will:

1. **Provide Guidance**: Offer suggestions and best practices when writing code
2. **Enforce Standards**: Flag code that doesn't meet the defined standards
3. **Automate Repetitive Tasks**: Generate boilerplate code, documentation, and tests
4. **Improve Security**: Identify potential security vulnerabilities
5. **Optimise Performance**: Suggest performance improvements

### Rule Customisation

You can customise the rules by:

1. **Editing Rule Files**: Modify the `.mdc` files to match your project's specific requirements
2. **Adding New Rules**: Create new `.mdc` files following the same format
3. **Disabling Rules**: Remove or rename rule files you don't want to use
4. **Organizing into Subdirectories**: Cursor supports organizing rules into subdirectories within `.cursor/rules/`

#### Organizing Rules into Subdirectories

Cursor **supports subdirectories** within `.cursor/rules/` for better organization. You can structure your rules like this:

```
.cursor/rules/
├── security/
│   ├── drupal-authentication-failures.mdc
│   ├── javascript-broken-access-control.mdc
│   └── python-injection.mdc
├── database/
│   ├── sql-prisma.mdc
│   └── drupal-database-standards.mdc
├── frontend/
│   ├── frontend-react.mdc
│   ├── react-patterns.mdc
│   └── tailwind-standards.mdc
└── core/
    └── cursor-rules.mdc
```

**Key Points:**
- ✅ **Auto-discovery works**: Cursor automatically discovers rules in subdirectories recursively
- ✅ **Same functionality**: Rules in subdirectories work identically to rules in the root directory
- ✅ **Installer support**: The installer now supports installing rules to subdirectories automatically
- ⚠️ **Submodule awareness**: Cursor may discover rules in submodules/nested projects. Use `.cursorignore` to exclude specific directories if needed

For more details, see [`.cursor/rules/core/cursor-rules.mdc`](.cursor/rules/core/cursor-rules.mdc).

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Commit Message Standards

This project follows the [Conventional Commits](https://www.conventionalcommits.org/) specification. Commit messages should be structured as follows:

```
<type>: <description>

[optional body]

[optional footer(s)]
```

Types include:
- `fix`: for bug fixes
- `feat`: for new features
- `perf`: for performance improvements
- `docs`: for documentation updates
- `style`: for frontend changes (SCSS, Twig, etc.)
- `refactor`: for code refactoring
- `test`: for adding or updating tests
- `chore`: for maintenance tasks

Example: `feat: add support for Python security rules`

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgements

- [Cursor AI](https://cursor.sh/) for the amazing AI-powered code editor
- [Ivan Grynenko](https://github.com/ivangrynenko) for creating the original [cursor-rules repository](https://github.com/ivangrynenko/cursor-rules) that this project extends
- All contributors who have helped improve these rules

---

## 📊 Benefits of Using These Rules

### For Individual Developers

1. **Consistency**:
   - Maintain consistent coding style across projects
   - Reduce cognitive load when switching between tasks
   - Ensure best practices are followed even when under time pressure

2. **Efficiency**:
   - Automate repetitive coding tasks
   - Reduce time spent on boilerplate code
   - Get immediate feedback on code quality

3. **Learning**:
   - Learn best practices through contextual suggestions
   - Discover security vulnerabilities and how to fix them
   - Improve coding habits through consistent reinforcement

### For Teams

1. **Standardisation**:
   - Enforce team-wide coding standards
   - Reduce code review friction
   - Maintain consistent documentation

2. **Knowledge Sharing**:
   - Codify team knowledge in rules
   - Reduce onboarding time for new team members
   - Share best practices automatically

3. **Quality Assurance**:
   - Catch common issues before they reach code review
   - Ensure security best practices are followed
   - Maintain high code quality across the team

### For Organisations

1. **Governance**:
   - Enforce organisational standards
   - Ensure compliance with security requirements
   - Maintain consistent code quality across teams

2. **Efficiency**:
   - Reduce time spent on code reviews
   - Decrease technical debt accumulation
   - Streamline development processes

3. **Knowledge Management**:
   - Preserve institutional knowledge in rules
   - Simplified onboarding for new team members

### Recommendations for Users

1. **Selective Rule Usage**:
   - Disable rules not relevant to your specific technology stack
   - Configure rule priorities based on your project's needs
   - Consider creating custom installation scripts that only install relevant rules

2. **Performance Optimisation**:
   - If experiencing slowdowns, review which rules are most frequently triggered
   - Consider disabling computationally expensive rules for very large files
   - Report performance issues so rule patterns can be optimised

3. **Custom Rule Development**:
   - When creating custom rules, follow the patterns established in existing rules
   - Use specific file filters to minimise unnecessary rule evaluation
   - Test new rules thoroughly in isolation before adding to the collection

### Future Scalability Plans

While maintaining all rules in a single repository currently provides the best developer experience, we're preparing for potential future growth:

1. **Enhanced Categorisation**:
   - Rules include clear language/framework tagging with a structured hierarchical system (As seen in the OWASP Top Ten Rules):
     - `language:php` - Explicitly identifies the programming language
     - `framework:drupal` - Specifies the framework or CMS
     - `category:security` - Defines the primary functional category
     - `subcategory:injection` - Provides more granular categorisation (e.g., injection, authentication)
     - `standard:owasp-top10` - Identifies the security standard being applied
     - `risk:a01-broken-access-control` - Specifies the exact risk identifier
   - This tagging system enables selective installation based on language, framework, or security concern
   - Installation scripts can target specific categories (e.g., only install PHP rules or only OWASP rules)

2. **Modular Design**:
   - Rule file structure supports potential future separation
   - Consistent naming conventions facilitate organisation

3. **Monitoring and Feedback**:
   - Repository growth and performance impacts are monitored
   - User feedback helps identify optimisation opportunities

If you encounter any issues with rule management or have suggestions for improving organisation, please submit an issue or pull request.