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
#ifndef ACCOUNT_POSIX_ADAPTER_INCLUDE_ACCOUNT_POSIX_TOOLS_H
#define ACCOUNT_POSIX_ADAPTER_INCLUDE_ACCOUNT_POSIX_TOOLS_H
#include <cstdint>
#include <grp.h>
#include <pwd.h>
#include <map>
#include <string>
#include <sys/types.h>
#include <vector>
#include "errors.h"

namespace OHOS {
namespace AccountSA {

class PosixDataMap {
public:
    PosixDataMap() = default;
    ErrCode GetAccountNameByLocalId(int32_t localId, std::string &accountName);
    ErrCode GetLocalIdByAccountName(const std::string &accountName, int32_t &localId);
    void DeleteByLocalId(int32_t localId);
    void ModifyByLocalId(int32_t localId, const std::string &accountName);
    std::string ToString();
    ErrCode FromString(const std::string &dataStr);
private:
    std::map<int32_t, std::string> posixDataMap_;
};

class CppPasswdType {
public:
    std::string pw_name = "";
    const std::string pw_passwd = "x";
    uid_t pw_uid = 0;
    gid_t pw_gid = 0;
    const std::string pw_gecos = "";
    const std::string pw_dir = "";
    const std::string pw_shell = "";
    size_t GetBufSize();
    ErrCode CopyToOutput(struct passwd *pw, char *buf, size_t size);
};

class CppGroupType {
public:
    std::string gr_name = "";
    const std::string gr_passwd = "";
    gid_t gr_gid = 0;
    const char *gr_mem = NULL;
    size_t GetBufSize();
    ErrCode CopyToOutput(struct group *pw, char *buf, size_t size);
};

class PosixTools {
public:
    static bool CheckAccountNameValid(const std::string &accountName);
    static ErrCode WritePosixMapFile(const std::string &content);
    static ErrCode ReadPosixMapFile(std::string &content);
    static ErrCode IsPosixMapFileExist(bool &isExist);
    static ErrCode CreateFaultFlagFile();
    static ErrCode RemoveFaultFlagFile();
    static ErrCode IsFaultFlagFileExist(bool &isExist);

    static int32_t GetLocalIdFromUid(int32_t uid);
    static int32_t GetAppIdFromUid(int32_t uid);
    static std::string GenerateGroupName(const std::string &accountName, const int32_t appIdx = 0);
    static int32_t SplitGroupName(const std::string &groupName, std::string &accountName, int32_t &appIdx);
    static int32_t GenerateUid(int32_t localId, int32_t appIdx = 0);
};

} // namespace AccountSA
} // namespace OHOS

#endif // ACCOUNT_POSIX_ADAPTER_INCLUDE_ACCOUNT_POSIX_TOOLS_H