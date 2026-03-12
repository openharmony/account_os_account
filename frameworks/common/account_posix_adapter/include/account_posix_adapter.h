/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef ACCOUNT_POSIX_ADAPTER_INCLUDE_ACCOUNT_POSIX_ADAPTER_H
#define ACCOUNT_POSIX_ADAPTER_INCLUDE_ACCOUNT_POSIX_ADAPTER_H
#include <cinttypes>
#include <grp.h>
#include <pwd.h>
#include <sys/types.h>

namespace OHOS {
namespace AccountSA {
extern "C" {
/**
 * @brief Get real username for the specified user ID.
 * @param uid The user ID to query.
 * @return Returns a pointer to the real username string, or nullptr if not found.
 * @note This function is thread-safe.
 *       The returned pointer is statically allocated and should not be freed.
 */
char* __attribute__((visibility("default"))) oh_getusername(uid_t uid);

/**
 * @brief Get real group name for the specified group ID.
 * @param gid The group ID to query.
 * @return Returns a pointer to the real group name string, or nullptr if not found.
 * @note This function is thread-safe.
 *       The returned pointer is statically allocated and should not be freed.
 */
char* __attribute__((visibility("default"))) oh_getgroupname(gid_t gid);

/**
 * @brief Get password file entry by user ID.
 * @param uid The user ID to query.
 * @return Returns a pointer to passwd structure containing principal name (username_appid format),
 *         or nullptr if not found.
 * @warning This function is NOT thread-safe. Use oh_getpwuid_r() for thread-safe operation.
 * @note The returned pointer is statically allocated and may be overwritten by subsequent calls.
 */
struct passwd* __attribute__((visibility("default"))) oh_getpwuid(uid_t uid);

/**
 * @brief Get password file entry by user ID (thread-safe reentrant version).
 * @param uid The user ID to query.
 * @param pw Pointer to passwd structure to be filled.
 * @param buf Buffer for storing string data.
 * @param size Size of buffer in bytes.
 * @param res Pointer to result pointer (set to pw on success, nullptr on failure).
 * @return Returns 0 on success, or an error number on failure.
 * @note This function is thread-safe reentrant version of oh_getpwuid().
 */
int32_t __attribute__((visibility("default")))
oh_getpwuid_r(uid_t uid, struct passwd *pw, char *buf, size_t size, struct passwd **res);

/**
 * @brief Get password file entry by principal name.
 * @param name The principal name to query (username_appid format).
 * @return Returns a pointer to passwd structure, or nullptr if not found.
 * @warning This function is NOT thread-safe. Use oh_getpwnam_r() for thread-safe operation.
 * @note The returned pointer is statically allocated and may be overwritten by subsequent calls.
 */
struct passwd* __attribute__((visibility("default"))) oh_getpwnam(const char *name);

/**
 * @brief Get password file entry by principal name (thread-safe reentrant version).
 * @param name The principal name to query (username_appid format).
 * @param pw Pointer to passwd structure to be filled.
 * @param buf Buffer for storing string data.
 * @param size Size of buffer in bytes.
 * @param res Pointer to result pointer (set to pw on success, nullptr on failure).
 * @return Returns 0 on success, or an error number on failure.
 * @note This function is thread-safe reentrant version of oh_getpwnam().
 */
int32_t __attribute__((visibility("default")))
oh_getpwnam_r(const char *name, struct passwd *pw, char *buf, size_t size, struct passwd **res);

/**
 * @brief Get group file entry by group ID.
 * @param gid The group ID to query.
 * @return Returns a pointer to group structure containing principal name (username_appid format),
 *         or nullptr if not found.
 * @warning This function is NOT thread-safe. Use oh_getgrgid_r() for thread-safe operation.
 * @note The returned pointer is statically allocated and may be overwritten by subsequent calls.
 */
struct group* __attribute__((visibility("default"))) oh_getgrgid(gid_t gid);

/**
 * @brief Get group file entry by group ID (thread-safe reentrant version).
 * @param gid The group ID to query.
 * @param gr Pointer to group structure to be filled.
 * @param buf Buffer for storing string data.
 * @param size Size of buffer in bytes.
 * @param res Pointer to result pointer (set to gr on success, nullptr on failure).
 * @return Returns 0 on success, or an error number on failure.
 * @note This function is thread-safe reentrant version of oh_getgrgid().
 */
int32_t __attribute__((visibility("default")))
oh_getgrgid_r(gid_t gid, struct group *gr, char *buf, size_t size, struct group **res);

/**
 * @brief Get group file entry by principal name.
 * @param name The principal name to query (username_appid format).
 * @return Returns a pointer to group structure, or nullptr if not found.
 * @warning This function is NOT thread-safe. Use oh_getgrnam_r() for thread-safe operation.
 * @note The returned pointer is statically allocated and may be overwritten by subsequent calls.
 */
struct group* __attribute__((visibility("default"))) oh_getgrnam(const char *name);

/**
 * @brief Get group file entry by principal name (thread-safe reentrant version).
 * @param name The principal name to query (username_appid format).
 * @param gr Pointer to group structure to be filled.
 * @param buf Buffer for storing string data.
 * @param size Size of buffer in bytes.
 * @param res Pointer to result pointer (set to gr on success, nullptr on failure).
 * @return Returns 0 on success, or an error number on failure.
 * @note This function is thread-safe reentrant version of oh_getgrnam().
 */
int32_t __attribute__((visibility("default")))
oh_getgrnam_r(const char *name, struct group *gr, char *buf, size_t size, struct group **res);
}
} // namespace AccountSA
} // namespace OHOS
#endif // ACCOUNT_POSIX_ADAPTER_INCLUDE_ACCOUNT_POSIX_ADAPTER_H
