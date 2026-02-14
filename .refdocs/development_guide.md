# OS Account Management - Development Guide

---

## Basic Information

| Property | Value |
|----------|-------|
| **Repository Name** | os_account |
| **Subsystem** | account |
| **Primary Language** | C++ |
| **Last Updated** | 2026-01-31 |
| **System Ability ID** | 200 (accountmgr) |

---

## Development Guide

### Quick Start

1. Read [README.md](README.md) for general overview
2. Review [CLAUDE.md](CLAUDE.md) for AI-specific guidance
3. Explore [os_account.gni](os_account.gni) for build configuration
4. Check [services/accountmgr/BUILD.gn](services/accountmgr/BUILD.gn) for service structure

### Adding New Features

1. **Feature Flag**: Add flag in `os_account.gni` if conditional
2. **Interfaces**: Define API in appropriate `interfaces/` directory
3. **Framework**: Implement framework logic in `frameworks/`
4. **Service**: Add service implementation in `services/accountmgr/src/`
5. **Build**: Update BUILD.gn files with new sources
6. **Tests**: Add unit tests in `services/accountmgr/test/unittest/`

---

## Version History

| Version | Date | Changes | Maintainer |
|---------|------|---------|------------|
| v1.0 | 2026-01-31 | Initial development_guide.md creation | yujann |

**End of Document**