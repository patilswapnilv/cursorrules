# Changelog

All notable changes to this project are documented in this file. Entries appear in reverse chronological order so the most recent updates are always at the top. Do not overwrite existing content—prepend new releases instead.

## [Unreleased] - 2025-12-05
### Added
- **Major Restructuring:** Organized all rules into subdirectories for better maintainability:
  - `core/` - Core/essential rules
  - `security/` - All OWASP & security rules (Drupal, JavaScript, Python, WordPress)
  - `database/` - Database-related rules (SQL, Prisma, Drupal, WordPress)
  - `frontend/` - Frontend rules (React, Vue, Tailwind, JavaScript)
  - `drupal/` - Drupal-specific development rules
  - `wordpress/` - WordPress-specific development rules
  - `backend/` - Backend/server-side rules (TypeScript/Node.js, Python)
  - `devops/` - DevOps & infrastructure rules
  - `development/` - Development process rules
- **WordPress Security Rules:** Created 10 complete OWASP Top 10 security rule files for WordPress:
  - `security/wordpress-authentication-failures.mdc`
  - `security/wordpress-broken-access-control.mdc`
  - `security/wordpress-cryptographic-failures.mdc`
  - `security/wordpress-injection.mdc`
  - `security/wordpress-insecure-design.mdc`
  - `security/wordpress-integrity-failures.mdc`
  - `security/wordpress-logging-failures.mdc`
  - `security/wordpress-security-misconfiguration.mdc`
  - `security/wordpress-ssrf.mdc`
  - `security/wordpress-vulnerable-components.mdc`
- **WordPress Development Rules:** Created WordPress development standards files:
  - `wordpress/php-wordpress-best-practices.mdc`
  - `wordpress/php-wordpress-development-standards.mdc`
  - `wordpress/wordpress-file-permissions.mdc`
  - `database/wordpress-database-standards.mdc`
- **Subdirectory Support Documentation:** Documented Cursor's support for organizing rules into subdirectories

### Changed
- Renamed `wordpress-php.mdc` to `php-wordpress-standards.mdc` for consistency with Drupal naming
- Updated `install.php` to handle subdirectory structure:
  - Added `get_rule_path()` mapping function for backward compatibility
  - Updated GitHub URLs to include subdirectory paths
  - Enhanced file operations to create subdirectories as needed
  - Maintained backward compatibility with flat structure
- Updated all documentation (`README.md`, `AGENTS.md`) with new file paths
- Updated `.cursor/rules/core/cursor-rules.mdc` to document subdirectory support

### Technical Details
- **Total Rules:** 90 files (up from ~70)
- **New Files:** 14 WordPress rule files created
- **Structure:** All rules now organized into 9 logical subdirectories
- **Backward Compatibility:** Installer supports both old flat and new subdirectory structures

## [1.1.0] - 2025-10-27
### Changed
- Restructured the full Cursor rule bundle set with consistent sections for details, filters, rejections, and suggestions to improve readability and maintenance.
- Incremented internal rule metadata versions across all affected files to reflect the new structure.

## [1.0.8] - 2025-10-24
### Added
- Integrated installation of Cursor slash commands, including project/home/both targets and new `--commands` / `--skip-commands` flags.
- Captured command installation outcomes in generated `AGENTS.md` and `UPDATE.md` files for downstream visibility.

### Changed
- Bumped `CURSOR_RULES_VERSION` to `1.0.8` in preparation for the next release cycle.

## [1.0.7] - 2025-09-02
### Changed
- Streamlined rule bundle organisation and refreshed documentation references to match the markdown migration.
- Tweaked installer configuration and associated file-mapping tests for the updated structure.

## [1.0.6] - 2025-08-20
### Added
- **AGENTS.md Documentation:** Added comprehensive AGENTS.md guide for using Cursor Rules with Cursor AI
  - Links to all rule bundles (Core, Web Stack, Python, JavaScript Security)
  - Tag-based selection documentation and examples
  - Installation options reference guide

### Changed
- Updated release metadata to version 1.0.6 in preparation for distribution.

### Fixed
- **Installer Improvements:**
  - Fixed hanging issue when piping installer through curl
  - Added proper STDIN handling for piped execution
  - Improved argument parsing for curl-based installation
  - Added fclose(STDIN) to prevent PHP from waiting for input after completion
- **Bug Fixes:**
  - Resolved script hanging when using `curl ... | php` commands
  - Fixed argument parsing when using `--` separator with piped input
  - Corrected PHP_SELF detection for piped execution

## [1.0.5] - 2025-01-03
### Added
- **Enhanced Multi-Language Support:**
  - Added comprehensive support for all languages in cursor rules (PHP, Python, JavaScript, TypeScript, CSS, HTML)
  - Implemented language-specific coding standards and security practices
  - Added framework-specific guidelines (Drupal, Django, React, Vue.js, Express.js)
- **Large File Detection and Skipping:**
  - Added logic to skip compiled/minified files (>1MB, *.min.*, *-bundle.*, etc.)
  - Implemented vendor directory filtering (node_modules/, vendor/, dist/, build/)
  - Added auto-generated file detection to focus on source code only
- **Improved Security Assessment:**
  - Language-specific security checks (SQL injection, XSS, command injection)
  - Framework-aware security considerations
  - OWASP compliance across all supported languages
- **Enhanced Label Management:**
  - Added language-specific labels (lang/php, lang/python, lang/javascript, etc.)
  - Automatic language detection based on file extensions
  - Technology-specific colour coding using official language colours
- **Technology Detection Process:**
  - File extension analysis for automatic language identification
  - Framework detection through config files (package.json, composer.json, etc.)
  - Project structure analysis for framework patterns
  - Dependency analysis and build tool detection
- **Updated Review Checklist:**
  - File analysis requirements with mandatory large file skipping
  - Language-specific sections for targeted reviews
  - Enhanced security focus across all technologies
  - Performance considerations for each language

### Changed
- Updated installer metadata to version 1.0.5 and refreshed `.cursor/UPDATE.md` with detailed release notes.

## [0.1.0] - 2025-06-01
### Added
- Enhanced GitHub Actions workflow and extended automated test coverage for installer scenarios, including ignore-file and tag option handling.

### Changed
- Updated test utilities and file maps to support the expanded rule set.

## [0.0.2] - 2025-02-28
### Added
- Introduced local rule fallback logic to `install.php`, ensuring installation succeeds when remote downloads are unavailable.
- Added `testing-guidelines.mdc` to the default installation set and documented the new behaviour.

## [0.0.1] - 2025-02-12
### Changed
- Improved installer robustness with better piped-input handling, simplified error messaging, and streamlined logic.

---

## Fork Origin

This project was forked from the [original cursor-rules repository](https://github.com/ivangrynenko/cursor-rules) by [Ivan Grynenko](https://github.com/ivangrynenko) and extended to support a **full polyglot stack**, providing specialized rules for modern development workflows across diverse technology ecosystems.

**Original Repository:** https://github.com/ivangrynenko/cursor-rules

**Key Extensions:**
- Expanded from PHP/Drupal focus to support multiple languages (PHP, Python, JavaScript, TypeScript, etc.)
- Added comprehensive OWASP Top 10 security rules for multiple languages and frameworks
- Added WordPress-specific rules and standards
- Added frontend framework rules (React, Vue, Next.js)
- Added backend framework rules (NestJS, Express, Fastify)
- Added database and ORM rules (Prisma, SQL, Neo4j)
- Added DevOps and infrastructure rules
- Enhanced installer with tag-based selection and subdirectory support
