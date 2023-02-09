/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "account_file_operator.h"
#include <cerrno>
#include <cstdio>
#include <fstream>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef WITH_SELINUX
#include <policycoreutils.h>
#endif // WITH_SELINUX
#include "account_log_wrapper.h"
#include "directory_ex.h"
#include "hisysevent_adapter.h"
namespace OHOS {
namespace AccountSA {
AccountFileOperator::AccountFileOperator()
{}

AccountFileOperator::~AccountFileOperator()
{}

ErrCode AccountFileOperator::CreateDir(const std::string &path)
{
    ACCOUNT_LOGD("enter");

    if (!OHOS::ForceCreateDirectory(path)) {
        ACCOUNT_LOGE("failed to create %{public}s, errno %{public}d.", path.c_str(), errno);
        return ERR_OSACCOUNT_SERVICE_FILE_CREATE_DIR_ERROR;
    }
    mode_t mode = S_IRWXU;
    bool createFlag = OHOS::ChangeModeDirectory(path, mode);
    if (!createFlag) {
        ACCOUNT_LOGE("failed to change mode for %{public}s, errno %{public}d.", path.c_str(), errno);
        return ERR_OSACCOUNT_SERVICE_FILE_CHANGE_DIR_MODE_ERROR;
    }

    return ERR_OK;
}

ErrCode AccountFileOperator::DeleteDirOrFile(const std::string &path)
{
    bool delFlag = false;
    if (IsExistFile(path)) {
        delFlag = OHOS::RemoveFile(path);
    }
    if (IsExistDir(path)) {
        delFlag = OHOS::ForceRemoveDirectory(path);
    }
    if (!delFlag) {
        ACCOUNT_LOGE("DeleteDirOrFile failed, path %{public}s errno %{public}d.", path.c_str(), errno);
        return ERR_OSACCOUNT_SERVICE_FILE_DELE_ERROR;
    }

    return ERR_OK;
}

ErrCode AccountFileOperator::InputFileByPathAndContent(const std::string &path, const std::string &content)
{
    std::string str = path;
    str.erase(str.rfind('/'));
    if (!IsExistDir(str)) {
        ErrCode errCode = CreateDir(str);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("failed to create dir, str = %{public}s errCode %{public}d.", str.c_str(), errCode);
            return ERR_OSACCOUNT_SERVICE_FILE_FIND_DIR_ERROR;
        }
    }
    FILE *fp = fopen(path.c_str(), "wb");
    if (fp == nullptr) {
        ACCOUNT_LOGE("failed to open %{public}s, errno %{public}d.", path.c_str(), errno);
        return ERR_ACCOUNT_COMMON_FILE_OPEN_FAILED;
    }
    size_t num = fwrite(content.c_str(), sizeof(char), content.length(), fp);
    if (num != content.length()) {
        ACCOUNT_LOGE("failed to fwrite %{public}s, errno %{public}d.", path.c_str(), errno);
        fclose(fp);
        return ERR_ACCOUNT_COMMON_FILE_WRITE_FAILED;
    }
    if (fflush(fp) != 0) {
        ACCOUNT_LOGE("failed to fflush %{public}s, errno %{public}d.", path.c_str(), errno);
        fclose(fp);
        return ERR_ACCOUNT_COMMON_FILE_WRITE_FAILED;
    }
    if (fsync(fileno(fp)) != 0) {
        ACCOUNT_LOGE("failed to fsync %{public}s, errno %{public}d.", path.c_str(), errno);
        fclose(fp);
        return ERR_ACCOUNT_COMMON_FILE_WRITE_FAILED;
    }
    fclose(fp);
#ifdef WITH_SELINUX
    Restorecon(path.c_str());
#endif // WITH_SELINUX
    // change mode
    if (!ChangeModeFile(path, S_IRUSR | S_IWUSR)) {
        ACCOUNT_LOGW("failed to change mode for file %{public}s, errno %{public}d.", path.c_str(), errno);
    }

    return ERR_OK;
}

ErrCode AccountFileOperator::GetFileContentByPath(const std::string &path, std::string &content)
{
    if (!IsExistFile(path)) {
        ACCOUNT_LOGE("cannot find file, path = %{public}s", path.c_str());
        return ERR_OSACCOUNT_SERVICE_FILE_FIND_FILE_ERROR;
    }
    std::stringstream buffer;
    std::ifstream i(path);
    if (!i.is_open()) {
        ACCOUNT_LOGE("cannot open file %{public}s, errno %{public}d.", path.c_str(), errno);
        return ERR_ACCOUNT_COMMON_FILE_OPEN_FAILED;
    }
    buffer << i.rdbuf();
    content = buffer.str();
    i.close();
    return ERR_OK;
}

bool AccountFileOperator::IsExistFile(const std::string &path)
{
    if (path.empty()) {
        return false;
    }

    struct stat buf = {};
    if (stat(path.c_str(), &buf) != 0) {
        return false;
    }

    return S_ISREG(buf.st_mode);
}

bool AccountFileOperator::IsJsonFormat(const std::string &path)
{
    std::ifstream fin(path);
    if (!fin) {
        return false;
    }

    nlohmann::json jsonData = nlohmann::json::parse(fin, nullptr, false);
    fin.close();
    if (!jsonData.is_structured()) {
        return false;
    }
    return true;
}

bool AccountFileOperator::IsJsonFileReady(const std::string &path)
{
    return IsExistFile(path) && IsJsonFormat(path);
}

bool AccountFileOperator::IsExistDir(const std::string &path)
{
    if (path.empty()) {
        return false;
    }

    struct stat buf = {};
    if (stat(path.c_str(), &buf) != 0) {
        return false;
    }

    return S_ISDIR(buf.st_mode);
}
}  // namespace AccountSA
}  // namespace OHOS
