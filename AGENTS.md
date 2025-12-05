# Cursor Agents Guide (Using Cursor Rules)

This document explains how to use the rules in this repository with Cursor and serves as a single entry point that references the existing rule files. It avoids duplication by linking directly to the `.cursor/rules/*.mdc` sources.

If you installed these rules via the installer, a project‑local AGENTS.md can be generated that lists only the rules you chose. By default, the installer writes AGENTS.md if absent; it overwrites only when you pass `--yes`.

## How To Use With Cursor
- Open your project in Cursor. Rules under `.cursor/rules` are discovered automatically by Cursor (including subdirectories).
- Keep this AGENTS.md handy as your quick index to the rule set.
- For installation methods and advanced options, see `README.md`.
- **Note**: Cursor supports organizing rules into subdirectories (e.g., `.cursor/rules/security/`, `.cursor/rules/database/`). See `README.md` for details.

## Installation Options
For full installation details and examples, see `README.md`.
- Core rules only: `--core`
- Web stack (includes core): `--web-stack` or `--ws`
- Python (includes core): `--python`
- JavaScript security (includes core): `--javascript`
- All rules: `--all`
- Tag-based selection: `--tags "<expression>"` or `--tag-preset <name>`
- Ignore files control: `--ignore-files yes|no|ask`

Tag taxonomy is documented in `TAG_STANDARDS.md`.

## Rule Bundles (Source of Truth)
Below are the rule bundles and their rule files. Each item links directly to the authoritative file under `.cursor/rules/`.

### Core
- [.cursor/rules/core/cursor-rules.mdc](.cursor/rules/core/cursor-rules.mdc)
- [.cursor/rules/core/git-commit-standards.mdc](.cursor/rules/core/git-commit-standards.mdc)
- [.cursor/rules/core/github-actions-standards.mdc](.cursor/rules/core/github-actions-standards.mdc)
- [.cursor/rules/core/improve-cursorrules-efficiency.mdc](.cursor/rules/core/improve-cursorrules-efficiency.mdc)
- [.cursor/rules/core/pull-request-changelist-instructions.mdc](.cursor/rules/core/pull-request-changelist-instructions.mdc)
- [.cursor/rules/core/readme-maintenance-standards.mdc](.cursor/rules/core/readme-maintenance-standards.mdc)
- [.cursor/rules/core/testing-guidelines.mdc](.cursor/rules/core/testing-guidelines.mdc)
- [.cursor/rules/development/confluence-editing-standards.mdc](.cursor/rules/development/confluence-editing-standards.mdc)

### Web Stack
- [.cursor/rules/frontend/accessibility-standards.mdc](.cursor/rules/frontend/accessibility-standards.mdc)
- [.cursor/rules/development/api-standards.mdc](.cursor/rules/development/api-standards.mdc)
- [.cursor/rules/development/build-optimization.mdc](.cursor/rules/development/build-optimization.mdc)
- [.cursor/rules/development/code-generation-standards.mdc](.cursor/rules/development/code-generation-standards.mdc)
- [.cursor/rules/development/debugging-standards.mdc](.cursor/rules/development/debugging-standards.mdc)
- [.cursor/rules/devops/docker-compose-standards.mdc](.cursor/rules/devops/docker-compose-standards.mdc)
- [.cursor/rules/security/drupal-authentication-failures.mdc](.cursor/rules/security/drupal-authentication-failures.mdc)
- [.cursor/rules/security/drupal-broken-access-control.mdc](.cursor/rules/security/drupal-broken-access-control.mdc)
- [.cursor/rules/security/drupal-cryptographic-failures.mdc](.cursor/rules/security/drupal-cryptographic-failures.mdc)
- [.cursor/rules/database/drupal-database-standards.mdc](.cursor/rules/database/drupal-database-standards.mdc)
- [.cursor/rules/drupal/drupal-file-permissions.mdc](.cursor/rules/drupal/drupal-file-permissions.mdc)
- [.cursor/rules/security/drupal-injection.mdc](.cursor/rules/security/drupal-injection.mdc)
- [.cursor/rules/security/drupal-insecure-design.mdc](.cursor/rules/security/drupal-insecure-design.mdc)
- [.cursor/rules/security/drupal-integrity-failures.mdc](.cursor/rules/security/drupal-integrity-failures.mdc)
- [.cursor/rules/security/drupal-logging-failures.mdc](.cursor/rules/security/drupal-logging-failures.mdc)
- [.cursor/rules/security/drupal-security-misconfiguration.mdc](.cursor/rules/security/drupal-security-misconfiguration.mdc)
- [.cursor/rules/security/drupal-ssrf.mdc](.cursor/rules/security/drupal-ssrf.mdc)
- [.cursor/rules/security/drupal-vulnerable-components.mdc](.cursor/rules/security/drupal-vulnerable-components.mdc)
- [.cursor/rules/development/generic_bash_style.mdc](.cursor/rules/development/generic_bash_style.mdc)
- [.cursor/rules/frontend/javascript-performance.mdc](.cursor/rules/frontend/javascript-performance.mdc)
- [.cursor/rules/frontend/javascript-standards.mdc](.cursor/rules/frontend/javascript-standards.mdc)
- [.cursor/rules/devops/lagoon-docker-compose-standards.mdc](.cursor/rules/devops/lagoon-docker-compose-standards.mdc)
- [.cursor/rules/devops/lagoon-yml-standards.mdc](.cursor/rules/devops/lagoon-yml-standards.mdc)
- [.cursor/rules/development/multi-agent-coordination.mdc](.cursor/rules/development/multi-agent-coordination.mdc)
- [.cursor/rules/development/node-dependencies.mdc](.cursor/rules/development/node-dependencies.mdc)
- [.cursor/rules/drupal/php-drupal-best-practices.mdc](.cursor/rules/drupal/php-drupal-best-practices.mdc)
- [.cursor/rules/drupal/php-drupal-development-standards.mdc](.cursor/rules/drupal/php-drupal-development-standards.mdc)
- [.cursor/rules/drupal/php-memory-optimisation.mdc](.cursor/rules/drupal/php-memory-optimisation.mdc)
- [.cursor/rules/wordpress/php-wordpress-standards.mdc](.cursor/rules/wordpress/php-wordpress-standards.mdc)
- [.cursor/rules/wordpress/php-wordpress-best-practices.mdc](.cursor/rules/wordpress/php-wordpress-best-practices.mdc)
- [.cursor/rules/wordpress/php-wordpress-development-standards.mdc](.cursor/rules/wordpress/php-wordpress-development-standards.mdc)
- [.cursor/rules/wordpress/wordpress-file-permissions.mdc](.cursor/rules/wordpress/wordpress-file-permissions.mdc)
- [.cursor/rules/database/wordpress-database-standards.mdc](.cursor/rules/database/wordpress-database-standards.mdc)
- [.cursor/rules/development/project-definition-template.mdc](.cursor/rules/development/project-definition-template.mdc)
- [.cursor/rules/frontend/react-patterns.mdc](.cursor/rules/frontend/react-patterns.mdc)
- [.cursor/rules/frontend/frontend-react.mdc](.cursor/rules/frontend/frontend-react.mdc)
- [.cursor/rules/security/security-practices.mdc](.cursor/rules/security/security-practices.mdc)
- [.cursor/rules/security/secret-detection.mdc](.cursor/rules/security/secret-detection.mdc)
- [.cursor/rules/frontend/tailwind-standards.mdc](.cursor/rules/frontend/tailwind-standards.mdc)
- [.cursor/rules/development/tests-documentation-maintenance.mdc](.cursor/rules/development/tests-documentation-maintenance.mdc)
- [.cursor/rules/development/third-party-integration.mdc](.cursor/rules/development/third-party-integration.mdc)
- [.cursor/rules/backend/typescript-node.mdc](.cursor/rules/backend/typescript-node.mdc)
- [.cursor/rules/database/sql-prisma.mdc](.cursor/rules/database/sql-prisma.mdc)
- [.cursor/rules/development/messaging-queue-patterns.mdc](.cursor/rules/development/messaging-queue-patterns.mdc)
- [.cursor/rules/devops/infra-devops.mdc](.cursor/rules/devops/infra-devops.mdc)
- [.cursor/rules/devops/vortex-cicd-standards.mdc](.cursor/rules/devops/vortex-cicd-standards.mdc)
- [.cursor/rules/devops/vortex-scaffold-standards.mdc](.cursor/rules/devops/vortex-scaffold-standards.mdc)
- [.cursor/rules/frontend/vue-best-practices.mdc](.cursor/rules/frontend/vue-best-practices.mdc)
- [.cursor/rules/development/behat-steps.mdc](.cursor/rules/development/behat-steps.mdc)
- [.cursor/rules/development/behat-ai-guide.mdc](.cursor/rules/development/behat-ai-guide.mdc)

### Python
- [.cursor/rules/security/python-authentication-failures.mdc](.cursor/rules/security/python-authentication-failures.mdc)
- [.cursor/rules/security/python-broken-access-control.mdc](.cursor/rules/security/python-broken-access-control.mdc)
- [.cursor/rules/security/python-cryptographic-failures.mdc](.cursor/rules/security/python-cryptographic-failures.mdc)
- [.cursor/rules/backend/python-data.mdc](.cursor/rules/backend/python-data.mdc)
- [.cursor/rules/security/python-injection.mdc](.cursor/rules/security/python-injection.mdc)
- [.cursor/rules/security/python-insecure-design.mdc](.cursor/rules/security/python-insecure-design.mdc)
- [.cursor/rules/security/python-integrity-failures.mdc](.cursor/rules/security/python-integrity-failures.mdc)
- [.cursor/rules/security/python-logging-monitoring-failures.mdc](.cursor/rules/security/python-logging-monitoring-failures.mdc)
- [.cursor/rules/security/python-security-misconfiguration.mdc](.cursor/rules/security/python-security-misconfiguration.mdc)
- [.cursor/rules/security/python-ssrf.mdc](.cursor/rules/security/python-ssrf.mdc)
- [.cursor/rules/security/python-vulnerable-outdated-components.mdc](.cursor/rules/security/python-vulnerable-outdated-components.mdc)
- [.cursor/rules/security/security-practices.mdc](.cursor/rules/security/security-practices.mdc)

### JavaScript Security
- [.cursor/rules/security/javascript-broken-access-control.mdc](.cursor/rules/security/javascript-broken-access-control.mdc)
- [.cursor/rules/security/javascript-cryptographic-failures.mdc](.cursor/rules/security/javascript-cryptographic-failures.mdc)
- [.cursor/rules/security/javascript-identification-authentication-failures.mdc](.cursor/rules/security/javascript-identification-authentication-failures.mdc)
- [.cursor/rules/security/javascript-injection.mdc](.cursor/rules/security/javascript-injection.mdc)
- [.cursor/rules/security/javascript-insecure-design.mdc](.cursor/rules/security/javascript-insecure-design.mdc)
- [.cursor/rules/security/javascript-security-logging-monitoring-failures.mdc](.cursor/rules/security/javascript-security-logging-monitoring-failures.mdc)
- [.cursor/rules/security/javascript-security-misconfiguration.mdc](.cursor/rules/security/javascript-security-misconfiguration.mdc)
- [.cursor/rules/security/javascript-server-side-request-forgery.mdc](.cursor/rules/security/javascript-server-side-request-forgery.mdc)
- [.cursor/rules/security/javascript-software-data-integrity-failures.mdc](.cursor/rules/security/javascript-software-data-integrity-failures.mdc)
- [.cursor/rules/security/javascript-vulnerable-outdated-components.mdc](.cursor/rules/security/javascript-vulnerable-outdated-components.mdc)

## Tag-Based Selection
The installer supports tag expressions and presets. Examples:
- `--tags "language:javascript category:security"`
- `--tags "framework:react"`
- `--tags "language:php standard:owasp-top10"`
- `--tag-preset js-owasp`

See `TAG_STANDARDS.md` for the complete tag taxonomy and guidance.

## Maintainer Checklist
- Before opening a pull request, prepend a new entry to `CHANGELOG.md` describing your changes (latest release first) and never delete prior history.
- Ensure the summary in `CHANGELOG.md` matches the work being done and that `CURSOR_RULES_VERSION` reflects the next release number.
- Record key implementation notes in this `AGENTS.md` only when they affect installer behaviour or rule coverage so the instructions stay current.
- Regenerate project-local `AGENTS.md` files with `--yes` when you need to refresh them after significant rule or command updates.

## Updating Or Removing
- To update, re-run the installer with your preferred options (it will copy over updated rules). See `README.md`.
- To remove rules, delete files from `.cursor/rules` and remove any generated `.cursorignore` files if not needed.

## References
- Project README: [README.md](README.md)
- Tag standards: [TAG_STANDARDS.md](TAG_STANDARDS.md)
- All rule sources: `.cursor/rules/**/*.mdc` (includes subdirectories)
