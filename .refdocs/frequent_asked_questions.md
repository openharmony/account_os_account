# OS Account Management - FAQ

---

## Basic Information

| Property | Value |
|----------|-------|
| **Repository Name** | os_account |
| **Subsystem** | base/account |
| **Primary Language** | C++ |
| **Last Updated** | 2026-01-31 |
| **System Ability ID** | 200 (accountmgr) |

---

## Frequently Asked Questions

### Q1: How to debug account service startup failures or device boot failed?

**A**: Follow these steps:

1. **Check process status**:
   ```bash
   ps -ef | grep accountmgr
   ```

2. **View system logs**:
   ```bash
   hilog | grep -i "C01B00"
   ```

3. **Check faultlogs**:
   - Fault log is at `/data/log/faultlog/faultlogger` on device.

4. **Check first user is correctly started**:
   - The first user should be created automatically during boot, the entrance is `CreateBaseStandardAccount` at [inner_os_account_manager.cpp](../services/accountmgr/src/osaccount/inner_os_account_manager.cpp)
   - If the first user is created successfully, check whether the user is activated successfully, the entrance is `ActivateDefaultOsAccount` at [inner_os_account_manager.cpp](../services/accountmgr/src/osaccount/inner_os_account_manager.cpp)


---

### Q2: How to add a new account type?

**A**: Complete these steps:

1. Create new account framework in `frameworks/`
2. Implement interfaces (inherit from base account class)
3. Add service logic in `services/accountmgr/src/`
4. Define APIs in `interfaces/`
5. Write unit tests
6. Update AGENTS.md documentation

---

### Q3: Linker errors during build?

**A**: Common causes and solutions:

| Error | Cause | Solution |
|------|------|----------|
| `undefined reference` | Missing dependency | Add dependency in `BUILD.gn` |
| `multiple definition` | Duplicate definition | Check header include guards |

---

### Q4: How to run a single test case?

**A**:
```bash
./start.sh run -p rk3568 -t UT MST -tp os_account -ts OsAccountControlFileManagerModuleTest -tc OsAccountControlFileManagerUnitTest.OsAccountControlFileManagerTest001
```

---

### Q5: How to contribute code?

**A**: Code contribution workflow:

1. Fork OpenHarmony repository
2. Create feature branch
3. Write code and tests
4. Run full test suite
5. Submit Pull Request
6. Wait for code review

Ensure code meets:
- C++17 standard
- OpenHarmony coding style
- Unit test coverage > 80%

---

## Version History

| Version | Date | Changes | Maintainer |
|---------|------|---------|------------|
| v1.0 | 2026-01-31 | Initial frequent_asked_questions.md creation | yujann |

**End of Document**