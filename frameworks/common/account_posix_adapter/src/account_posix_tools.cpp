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

#include "account_posix_tools.h"
#include <algorithm>
#include <charconv>
#include <regex>
#include <securec.h>
#include <sstream>
#include "account_error_no.h"
#include "account_file_operator.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
namespace {
#ifndef ACCOUNT_TEST
const std::string ACCOUNT_POSIX_MAP_DIR = "/data/service/el1/public/for-all-app/account/";
#else
const std::string ACCOUNT_POSIX_MAP_DIR = "/data/service/el1/public/account/test/";
#endif // ACCOUNT_TEST
const std::string ACCOUNT_POSIX_MAP_NAME = "account_posix_map";
const std::string ACCOUNT_POSIX_MAP_FAULT_FLAG_NAME = ".fault_flag";
const char ACCOUNT_POSIX_MAP_DELIMITER = ':';
const int32_t UID_TRANSFORM_DIVISOR = 200000;
const std::string GROUP_NAME_DELIMITER = "_a";
};

ErrCode PosixDataMap::GetAccountNameByLocalId(int32_t localId, std::string &accountName)
{
    auto it = posixDataMap_.find(localId);
    if (it == posixDataMap_.end()) {
        ACCOUNT_LOGE("LocalId %{public}d not found", localId);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    accountName = it->second;
    return ERR_OK;
}

ErrCode PosixDataMap::GetLocalIdByAccountName(const std::string &accountName, int32_t &localId)
{
    auto it = std::find_if(posixDataMap_.begin(), posixDataMap_.end(),
        [&accountName](const auto &pair) { return pair.second == accountName; });
    if (it == posixDataMap_.end()) {
        ACCOUNT_LOGE("Account name not found");
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    localId = it->first;
    return ERR_OK;
}

void PosixDataMap::DeleteByLocalId(int32_t localId)
{
    auto it = posixDataMap_.find(localId);
    if (it == posixDataMap_.end()) {
        ACCOUNT_LOGE("LocalId %{public}d not found", localId);
        return;
    }
    posixDataMap_.erase(it);
}

void PosixDataMap::ModifyByLocalId(int32_t localId, const std::string &accountName)
{
    posixDataMap_[localId] = accountName;
}

std::string PosixDataMap::ToString()
{
    std::stringstream ss;
    for (const auto &each : posixDataMap_) {
        ss << each.first << ACCOUNT_POSIX_MAP_DELIMITER << each.second << '\n';
    }
    return ss.str();
}

ErrCode PosixDataMap::FromString(const std::string &dataStr)
{
    std::stringstream ss(dataStr);
    std::string line;
    std::map<int32_t, std::string> dataMap;
    while (std::getline(ss, line)) {
        size_t pos = line.find(ACCOUNT_POSIX_MAP_DELIMITER);
        if (pos != std::string::npos) {
            std::string localIdStr = line.substr(0, pos);
            std::string name = line.substr(pos + 1);
            int32_t localId = -1;
            auto res = std::from_chars(localIdStr.data(), localIdStr.data() + localIdStr.size(), localId);
            if (res.ec != std::errc()) {
                ACCOUNT_LOGE("Convert %{public}s to number failed, err=%{public}d", localIdStr.c_str(),
                    static_cast<int32_t>(res.ec));
                return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
            }
            dataMap[localId] = name;
        }
    }
    posixDataMap_ = std::move(dataMap);
    return ERR_OK;
}

bool PosixTools::CheckAccountNameValid(const std::string &accountName)
{
    std::regex invalidChar("[^a-zA-Z0-9._-]");
    if (accountName.empty() || std::regex_search(accountName, invalidChar)) {
        ACCOUNT_LOGE("Account name not satisfy special character rule");
        return false;
    }
    return true;
}

ErrCode PosixTools::WritePosixMapFile(const std::string &content)
{
    AccountFileOperator fileOperator;
    return fileOperator.InputFileByPathAndContentWithTransaction(
        ACCOUNT_POSIX_MAP_DIR + ACCOUNT_POSIX_MAP_NAME, content, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
}

ErrCode PosixTools::ReadPosixMapFile(std::string &content)
{
    AccountFileOperator fileOperator;
    return fileOperator.GetFileContentByPath(ACCOUNT_POSIX_MAP_DIR + ACCOUNT_POSIX_MAP_NAME, content);
}

ErrCode PosixTools::IsPosixMapFileExist(bool &isExist)
{
    AccountFileOperator fileOperator;
    ErrCode ret = fileOperator.CheckFileExistence(ACCOUNT_POSIX_MAP_DIR + ACCOUNT_POSIX_MAP_NAME);
    if (ret == ERR_ACCOUNT_COMMON_FILE_NOT_EXIST) {
        isExist = false;
        return ERR_OK;
    }
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Check posix map file existence failed, ret = %{public}d", ret);
        return ret;
    }
    isExist = true;
    return ERR_OK;
}

ErrCode PosixTools::CreateFaultFlagFile()
{
    AccountFileOperator fileOperator;
    return fileOperator.InputFileByPathAndContent(ACCOUNT_POSIX_MAP_DIR + ACCOUNT_POSIX_MAP_FAULT_FLAG_NAME, "");
}

ErrCode PosixTools::RemoveFaultFlagFile()
{
    AccountFileOperator fileOperator;
    return fileOperator.DeleteFile(ACCOUNT_POSIX_MAP_DIR + ACCOUNT_POSIX_MAP_FAULT_FLAG_NAME);
}

ErrCode PosixTools::IsFaultFlagFileExist(bool &isExist)
{
    isExist = false;
    AccountFileOperator fileOperator;
    ErrCode ret = fileOperator.CheckFileExistence(ACCOUNT_POSIX_MAP_DIR + ACCOUNT_POSIX_MAP_FAULT_FLAG_NAME);
    if (ret == ERR_ACCOUNT_COMMON_FILE_NOT_EXIST) {
        return ERR_OK;
    }
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Find fault flag file failed, ret = %{public}d", ret);
        return ret;
    }
    isExist = true;
    return ERR_OK;
}

int32_t PosixTools::GetLocalIdFromUid(int32_t uid)
{
    return uid / UID_TRANSFORM_DIVISOR;
}

int32_t PosixTools::GetAppIdFromUid(int32_t uid)
{
    return uid % UID_TRANSFORM_DIVISOR;
}

std::string PosixTools::GenerateGroupName(const std::string &accountName, const int32_t appIdx)
{
    return accountName + GROUP_NAME_DELIMITER + std::to_string(appIdx);
}

int32_t PosixTools::SplitGroupName(const std::string &groupName, std::string &accountName, int32_t &appIdx)
{
    size_t pos = groupName.rfind(GROUP_NAME_DELIMITER);
    if (pos == std::string::npos) {
        ACCOUNT_LOGE("Input group name is invalid");
        return EINVAL;
    }
    accountName = groupName.substr(0, pos);
    std::string appIdxStr = groupName.substr(pos + GROUP_NAME_DELIMITER.size());
    auto res = std::from_chars(appIdxStr.data(), appIdxStr.data() + appIdxStr.size(), appIdx);
    if (res.ec != std::errc()) {
        ACCOUNT_LOGE("Convert %{public}s to number failed, err=%{public}d", appIdxStr.c_str(),
            static_cast<int32_t>(res.ec));
        accountName.clear();
        return EINVAL;
    }
    return EOK;
}

int32_t PosixTools::GenerateUid(int32_t localId, int32_t appIdx)
{
    return localId * UID_TRANSFORM_DIVISOR + appIdx;
}

size_t CppPasswdType::GetBufSize()
{
    size_t size = 0;
    // add name size, need add '\0'
    size += (pw_name.size() + 1);
    size += (pw_passwd.size() + 1);
    size += (pw_gecos.size() + 1);
    size += (pw_dir.size() + 1);
    size += (pw_shell.size() + 1);
    return size;
}

int32_t CopyStringToBuf(char *buf, size_t &pos, size_t bufSize, const std::string &str)
{
    size_t writeSize = str.size();
    int32_t ret = memcpy_s(buf + pos, bufSize - pos, str.c_str(), writeSize);
    if (ret != EOK) {
        ACCOUNT_LOGE("Copy string failed, ret = %{public}d", ret);
        return ret;
    }
    pos += (writeSize + 1);
    return EOK;
}

ErrCode CppPasswdType::CopyToOutput(struct passwd *pw, char *buf, size_t size)
{
    size_t needSize = GetBufSize();
    if (needSize > size) {
        ACCOUNT_LOGE("Buf size not enough, has %{public}zu get %{public}zu", size, needSize);
        return ERANGE;
    }
    int32_t ret = memset_s(buf, size, 0, size);
    if (ret != EOK) {
        ACCOUNT_LOGE("Memset_s failed, ret = %{public}d", ret);
        return ret;
    }
    pw->pw_name = buf;
    size_t pos = 0;
    ret = CopyStringToBuf(buf, pos, size, pw_name);
    if (ret != EOK) {
        ACCOUNT_LOGE("Copy pw_name failed, ret = %{public}d", ret);
        return ret;
    }
    pw->pw_passwd = buf + pos;
    ret = CopyStringToBuf(buf, pos, size, pw_passwd);
    if (ret != EOK) {
        ACCOUNT_LOGE("Copy pw_passwd failed, ret = %{public}d", ret);
        return ret;
    }
    pw->pw_gecos = buf + pos;
    ret = CopyStringToBuf(buf, pos, size, pw_gecos);
    if (ret != EOK) {
        ACCOUNT_LOGE("Copy pw_gecos failed, ret = %{public}d", ret);
        return ret;
    }
    pw->pw_dir = buf + pos;
    ret = CopyStringToBuf(buf, pos, size, pw_dir);
    if (ret != EOK) {
        ACCOUNT_LOGE("Copy pw_dir failed, ret = %{public}d", ret);
        return ret;
    }
    pw->pw_shell = buf + pos;
    ret = CopyStringToBuf(buf, pos, size, pw_shell);
    if (ret != EOK) {
        ACCOUNT_LOGE("Copy pw_shell failed, ret = %{public}d", ret);
        return ret;
    }
    pw->pw_uid = pw_uid;
    pw->pw_gid = pw_gid;
    return ERR_OK;
}

size_t CppGroupType::GetBufSize()
{
    size_t size = 0;
    // add name size, need add '\0'
    size += (gr_name.size() + 1);
    size += (gr_passwd.size() + 1);
    return size;
}

ErrCode CppGroupType::CopyToOutput(struct group *gr, char *buf, size_t size)
{
    size_t needSize = GetBufSize();
    if (needSize > size) {
        ACCOUNT_LOGE("Buf size not enough, has %{public}zu get %{public}zu", size, needSize);
        return ERANGE;
    }
    int32_t ret = memset_s(buf, size, 0, size);
    if (ret != EOK) {
        ACCOUNT_LOGE("Memset_s failed, ret = %{public}d", ret);
        return ret;
    }
    gr->gr_name = buf;
    size_t pos = 0;
    ret = CopyStringToBuf(buf, pos, size, gr_name);
    if (ret != EOK) {
        ACCOUNT_LOGE("Copy gr_name failed, ret = %{public}d", ret);
        return ret;
    }
    gr->gr_passwd = buf + pos;
    ret = CopyStringToBuf(buf, pos, size, gr_passwd);
    if (ret != EOK) {
        ACCOUNT_LOGE("Copy gr_passwd failed, ret = %{public}d", ret);
        return ret;
    }
    gr->gr_gid = gr_gid;
    // gr_mem is not supported, set to NULL
    gr->gr_mem = NULL;
    return ERR_OK;
}
} // namespace AccountSA
} // namespace OHOS