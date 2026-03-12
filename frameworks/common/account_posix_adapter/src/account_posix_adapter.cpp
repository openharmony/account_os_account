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

#include "account_posix_adapter.h"
#include <optional>
#include <securec.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "account_posix_tools.h"

namespace OHOS {
namespace AccountSA {
namespace {
const size_t BUF_SIZE = 1024;
static char g_passwdBuf[BUF_SIZE] = {0};
static struct passwd g_passwd = {
    .pw_name = NULL,
    .pw_passwd = NULL,
    .pw_uid = 0,
    .pw_gid = 0,
    .pw_gecos = NULL,
    .pw_dir = NULL,
    .pw_shell = NULL,
};
static char g_groupBuf[BUF_SIZE] = {0};
static struct group g_group = {
    .gr_name = NULL,
    .gr_passwd = NULL,
    .gr_gid = 0,
    .gr_mem = NULL,
};
};

int32_t GetRealAccountName(const int32_t uid, std::string &accountName)
{
    std::string content;
    int32_t ret = PosixTools::ReadPosixMapFile(content);
    if (ret != EOK) {
        ACCOUNT_LOGE("Read file failed, ret = %{public}d", ret);
        return EIO;
    }
    PosixDataMap posixDataMap;
    ret = posixDataMap.FromString(content);
    if (ret != EOK) {
        ACCOUNT_LOGE("Parse file data failed, ret = %{public}d", ret);
        return EIO;
    }
    int32_t localId = PosixTools::GetLocalIdFromUid(uid);
    ret = posixDataMap.GetAccountNameByLocalId(localId, accountName);
    if (ret != EOK) {
        ACCOUNT_LOGW("LocalId %{public}d not found", localId);
        accountName.clear();
        return EOK;
    }
    if (!PosixTools::CheckAccountNameValid(accountName)) {
        ACCOUNT_LOGW("Account name is invalid");
        accountName.clear();
    }
    return EOK;
}

int32_t GetAccountLocalId(const std::string &accountName, std::optional<int32_t> &localId)
{
    if (!PosixTools::CheckAccountNameValid(accountName)) {
        ACCOUNT_LOGW("Account name is invalid");
        localId = std::nullopt;
        return EOK;
    }
    std::string content;
    int32_t ret = PosixTools::ReadPosixMapFile(content);
    if (ret != EOK) {
        ACCOUNT_LOGE("Read file failed, ret = %{public}d", ret);
        return EIO;
    }
    PosixDataMap posixDataMap;
    ret = posixDataMap.FromString(content);
    if (ret != EOK) {
        ACCOUNT_LOGE("Parse file data failed, ret = %{public}d", ret);
        return EIO;
    }
    int32_t tmpId = 0;
    ret = posixDataMap.GetLocalIdByAccountName(accountName, tmpId);
    if (ret != EOK) {
        ACCOUNT_LOGW("Account name not found");
        localId = std::nullopt;
    } else {
        localId = tmpId;
    }
    return EOK;
}

char *oh_getusername(uid_t uid)
{
    int32_t i32Uid = static_cast<int32_t>(uid);
    std::string accountName = "";
    int32_t ret = GetRealAccountName(i32Uid, accountName);
    errno = ret;
    if (ret != EOK || accountName.empty()) {
        return NULL;
    }
    static thread_local char buf[BUF_SIZE] = {0};
    int32_t copyRet = memcpy_s(buf, BUF_SIZE, accountName.c_str(), accountName.size());
    if (copyRet != EOK) {
        ACCOUNT_LOGE("Copy account name failed, ret = %{public}d", copyRet);
        errno = copyRet;
        return NULL;
    }
    return buf;
}

char *oh_getgroupname(gid_t gid)
{
    int32_t uid = static_cast<int32_t>(gid);
    std::string accountName = "";
    int32_t ret = GetRealAccountName(uid, accountName);
    errno = ret;
    if (ret != EOK || accountName.empty()) {
        return NULL;
    }
    static thread_local char buf[BUF_SIZE] = {0};
    int32_t copyRet = memcpy_s(buf, BUF_SIZE, accountName.c_str(), accountName.size());
    if (copyRet != EOK) {
        ACCOUNT_LOGE("Copy account name failed, ret = %{public}d", copyRet);
        errno = copyRet;
        return NULL;
    }
    return buf;
}

struct passwd *oh_getpwuid(uid_t uid)
{
    int32_t i32Uid = static_cast<int32_t>(uid);
    std::string accountName = "";
    int32_t ret = GetRealAccountName(i32Uid, accountName);
    errno = ret;
    if (ret != EOK || accountName.empty()) {
        return NULL;
    }
    CppPasswdType cppPasswd;
    cppPasswd.pw_name = accountName;
    cppPasswd.pw_uid = uid;
    cppPasswd.pw_gid = static_cast<gid_t>(uid);
    ret = cppPasswd.CopyToOutput(&g_passwd, g_passwdBuf, BUF_SIZE);
    if (ret != EOK) {
        ACCOUNT_LOGE("Copy passwd to output failed, ret = %{public}d", ret);
        errno = ret;
        return NULL;
    }
    return &g_passwd;
}

int32_t oh_getpwuid_r(uid_t uid, struct passwd *pw, char *buf, size_t size, struct passwd **res)
{
    if ((pw == nullptr) || (buf == nullptr) || (res == nullptr)) {
        ACCOUNT_LOGW("Input ptr is null");
        errno = EINVAL;
        return EINVAL;
    }
    int32_t i32Uid = static_cast<int32_t>(uid);
    std::string accountName = "";
    *res = NULL;
    int32_t ret = GetRealAccountName(i32Uid, accountName);
    errno = ret;
    if (ret != EOK || accountName.empty()) {
        return ret;
    }
    CppPasswdType cppPasswd;
    cppPasswd.pw_name = accountName;
    cppPasswd.pw_uid = uid;
    cppPasswd.pw_gid = static_cast<gid_t>(uid);
    ret = cppPasswd.CopyToOutput(pw, buf, size);
    if (ret != EOK) {
        ACCOUNT_LOGE("Copy passwd to output failed, ret = %{public}d", ret);
        errno = ret;
        return ret;
    }
    *res = pw;
    return EOK;
}

struct passwd *oh_getpwnam(const char *name)
{
    if (name == nullptr) {
        ACCOUNT_LOGW("Input name is null");
        errno = EINVAL;
        return NULL;
    }
    std::string accountName(name);
    std::optional<int32_t> localId;
    int32_t ret = GetAccountLocalId(accountName, localId);
    errno = ret;
    if (ret != EOK || !localId.has_value()) {
        return NULL;
    }
    int32_t generatedUid = PosixTools::GenerateUid(localId.value());
    CppPasswdType cppPasswd;
    cppPasswd.pw_name = accountName;
    cppPasswd.pw_uid = static_cast<uid_t>(generatedUid);
    cppPasswd.pw_gid = static_cast<gid_t>(generatedUid);
    ret = cppPasswd.CopyToOutput(&g_passwd, g_passwdBuf, BUF_SIZE);
    if (ret != EOK) {
        ACCOUNT_LOGE("Copy passwd to output failed, ret = %{public}d", ret);
        errno = ret;
        return NULL;
    }
    return &g_passwd;
}

int32_t oh_getpwnam_r(const char *name, struct passwd *pw, char *buf, size_t size, struct passwd **res)
{
    if ((name == nullptr) || (pw == nullptr) || (buf == nullptr) || (res == nullptr)) {
        ACCOUNT_LOGW("Input ptr is null");
        errno = EINVAL;
        return EINVAL;
    }
    *res = NULL;
    std::string accountName(name);
    std::optional<int32_t> localId;
    int32_t ret = GetAccountLocalId(accountName, localId);
    errno = ret;
    if (ret != EOK || !localId.has_value()) {
        return ret;
    }
    int32_t generatedUid = PosixTools::GenerateUid(localId.value());
    CppPasswdType cppPasswd;
    cppPasswd.pw_name = accountName;
    cppPasswd.pw_uid = static_cast<uid_t>(generatedUid);
    cppPasswd.pw_gid = static_cast<gid_t>(generatedUid);
    ret = cppPasswd.CopyToOutput(pw, buf, size);
    if (ret != EOK) {
        ACCOUNT_LOGE("Copy passwd to output failed, ret = %{public}d", ret);
        errno = ret;
        return ret;
    }
    *res = pw;
    return EOK;
}

struct group *oh_getgrgid(gid_t gid)
{
    int32_t i32Uid = static_cast<int32_t>(gid);
    std::string accountName = "";
    int32_t ret = GetRealAccountName(i32Uid, accountName);
    errno = ret;
    if (ret != EOK || accountName.empty()) {
        return NULL;
    }
    CppGroupType cppGroup;
    cppGroup.gr_name = PosixTools::GenerateGroupName(accountName, PosixTools::GetAppIdFromUid(i32Uid));
    cppGroup.gr_gid = gid;
    ret = cppGroup.CopyToOutput(&g_group, g_groupBuf, BUF_SIZE);
    if (ret != EOK) {
        ACCOUNT_LOGE("Copy group to output failed, ret = %{public}d", ret);
        errno = ret;
        return NULL;
    }
    return &g_group;
}

int32_t oh_getgrgid_r(gid_t gid, struct group *gr, char *buf, size_t size, struct group **res)
{
    if ((gr == nullptr) || (buf == nullptr) || (res == nullptr)) {
        ACCOUNT_LOGW("Input ptr is null");
        errno = EINVAL;
        return EINVAL;
    }
    *res = NULL;
    int32_t i32Uid = static_cast<int32_t>(gid);
    std::string accountName = "";
    int32_t ret = GetRealAccountName(i32Uid, accountName);
    errno = ret;
    if (ret != EOK || accountName.empty()) {
        return ret;
    }
    CppGroupType cppGroup;
    cppGroup.gr_name = PosixTools::GenerateGroupName(accountName, PosixTools::GetAppIdFromUid(i32Uid));
    cppGroup.gr_gid = gid;
    ret = cppGroup.CopyToOutput(gr, buf, size);
    if (ret != EOK) {
        ACCOUNT_LOGE("Copy group to output failed, ret = %{public}d", ret);
        errno = ret;
        return ret;
    }
    *res = gr;
    return EOK;
}

struct group *oh_getgrnam(const char *name)
{
    if (name == nullptr) {
        ACCOUNT_LOGW("Input name is null");
        errno = EINVAL;
        return NULL;
    }
    std::string groupName(name);
    int32_t appIdx = 0;
    std::string accountName = "";
    int32_t ret = PosixTools::SplitGroupName(groupName, accountName, appIdx);
    if (ret != EOK) {
        ACCOUNT_LOGE("Group name is invalid");
        errno = ret;
        return NULL;
    }
    std::optional<int32_t> localId;
    ret = GetAccountLocalId(accountName, localId);
    errno = ret;
    if (ret != EOK || !localId.has_value()) {
        return NULL;
    }
    CppGroupType cppGroup;
    cppGroup.gr_name = groupName;
    cppGroup.gr_gid = static_cast<gid_t>(PosixTools::GenerateUid(localId.value(), appIdx));
    ret = cppGroup.CopyToOutput(&g_group, g_groupBuf, BUF_SIZE);
    if (ret != EOK) {
        ACCOUNT_LOGE("Copy group to output failed, ret = %{public}d", ret);
        errno = ret;
        return NULL;
    }
    return &g_group;
}

int32_t oh_getgrnam_r(const char *name, struct group *gr, char *buf, size_t size, struct group **res)
{
    if ((name == nullptr) || (gr == nullptr) || (buf == nullptr) || (res == nullptr)) {
        ACCOUNT_LOGW("Input ptr is null");
        errno = EINVAL;
        return EINVAL;
    }
    std::string groupName(name);
    int32_t appIdx = 0;
    std::string accountName = "";
    int32_t ret = PosixTools::SplitGroupName(groupName, accountName, appIdx);
    if (ret != EOK) {
        ACCOUNT_LOGE("Group name is invalid");
        errno = ret;
        return ret;
    }
    std::optional<int32_t> localId;
    ret = GetAccountLocalId(accountName, localId);
    errno = ret;
    if (ret != EOK || !localId.has_value()) {
        return ret;
    }
    CppGroupType cppGroup;
    cppGroup.gr_name = groupName;
    cppGroup.gr_gid = static_cast<gid_t>(PosixTools::GenerateUid(localId.value(), appIdx));
    ret = cppGroup.CopyToOutput(gr, buf, size);
    if (ret != EOK) {
        ACCOUNT_LOGE("Copy group to output failed, ret = %{public}d", ret);
        errno = ret;
        return ret;
    }
    *res = gr;
    return EOK;
}
} // namespace AccountSA
} // namespace OHOS