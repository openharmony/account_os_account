/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
#include <shared_mutex>
#include <sstream>
#include <string>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "account_log_wrapper.h"
#include "directory_ex.h"
#include "account_hisysevent_adapter.h"
namespace OHOS {
namespace AccountSA {
namespace {
const std::string ACCOUNT_INFO_DIGEST_FILE_PATH = "account_info_digest.json";
const long MAX_FILE_SIZE = 1 << 24; // 16MB
}
AccountFileOperator::AccountFileOperator()
{}

AccountFileOperator::~AccountFileOperator()
{}

ErrCode AccountFileOperator::CreateDir(const std::string &path)
{
    ACCOUNT_LOGD("enter");
    std::unique_lock<std::shared_timed_mutex> lock(fileLock_);
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
        std::unique_lock<std::shared_timed_mutex> lock(fileLock_);
        SetValidDeleteFileOperationFlag(path, true);
        delFlag = OHOS::RemoveFile(path);
    }
    if (IsExistDir(path)) {
        std::unique_lock<std::shared_timed_mutex> lock(fileLock_);
        SetValidDeleteFileOperationFlag(path, true);
        delFlag = OHOS::ForceRemoveDirectory(path);
    }
    if (!delFlag) {
        ACCOUNT_LOGE("DeleteDirOrFile failed, path %{public}s errno %{public}d.", path.c_str(), errno);
        SetValidDeleteFileOperationFlag(path, false);
        return ERR_OSACCOUNT_SERVICE_FILE_DELE_ERROR;
    }
    return ERR_OK;
}


void AccountFileOperator::SetValidModifyFileOperationFlag(const std::string &fileName, bool flag)
{
    if (fileName.find(ACCOUNT_INFO_DIGEST_FILE_PATH) != std::string::npos) { // ignore digest file record
        return;
    }
    if (!flag) {
        validModifyFileOperationFlag_.erase(
            std::remove(validModifyFileOperationFlag_.begin(), validModifyFileOperationFlag_.end(), fileName),
            validModifyFileOperationFlag_.end());
        return;
    }
    if (std::find(validModifyFileOperationFlag_.begin(), validModifyFileOperationFlag_.end(), fileName) ==
        validModifyFileOperationFlag_.end()) {
        validModifyFileOperationFlag_.emplace_back(fileName);
    }
}

bool AccountFileOperator::GetValidModifyFileOperationFlag(const std::string &fileName)
{
    for (auto iter : validModifyFileOperationFlag_) {
        if (iter == fileName) {
            return true;
        }
    }
    return false;
}

void AccountFileOperator::SetValidDeleteFileOperationFlag(const std::string &fileName, bool flag)
{
    if (!flag) {
        validDeleteFileOperationFlag_.erase(
            std::remove(validDeleteFileOperationFlag_.begin(), validDeleteFileOperationFlag_.end(), fileName),
            validDeleteFileOperationFlag_.end());
        return;
    }
    validDeleteFileOperationFlag_.emplace_back(fileName);
}

bool AccountFileOperator::GetValidDeleteFileOperationFlag(const std::string &fileName)
{
    for (auto iter : validDeleteFileOperationFlag_) {
        if (fileName.find(iter) != std::string::npos) {
            return true;
        }
    }
    return false;
}

ErrCode AccountFileOperator::InputFileByPathAndContent(const std::string &path, const std::string &content)
{
    std::string str = path;
    str.erase(str.rfind('/'));
    if (!IsExistDir(str)) {
        ErrCode errCode = CreateDir(str);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("failed to create dir, str = %{public}s errCode %{public}d.", str.c_str(), errCode);
            return errCode;
        }
    }
    std::unique_lock<std::shared_timed_mutex> lock(fileLock_);
    SetValidModifyFileOperationFlag(path, true);
    FILE *fp = fopen(path.c_str(), "wb");
    if (fp == nullptr) {
        ACCOUNT_LOGE("failed to open %{public}s, errno %{public}d.", path.c_str(), errno);
        SetValidModifyFileOperationFlag(path, false);
        return ERR_ACCOUNT_COMMON_FILE_OPEN_FAILED;
    }
    int fd = fileno(fp);
    do {
        flock(fd, LOCK_EX);
        size_t num = fwrite(content.c_str(), sizeof(char), content.length(), fp);
        if (num != content.length()) {
            ACCOUNT_LOGE("failed to fwrite %{public}s, errno %{public}d.", path.c_str(), errno);
            break;
        }
        if (fflush(fp) != 0) {
            ACCOUNT_LOGE("failed to fflush %{public}s, errno %{public}d.", path.c_str(), errno);
            break;
        }
        if (fsync(fd) != 0) {
            ACCOUNT_LOGE("failed to fsync %{public}s, errno %{public}d.", path.c_str(), errno);
            break;
        }
        flock(fd, LOCK_UN);
        fclose(fp);
        // change mode
        if (!ChangeModeFile(path, S_IRUSR | S_IWUSR)) {
            ACCOUNT_LOGW("failed to change mode for file %{public}s, errno %{public}d.", path.c_str(), errno);
            return ERR_OHOSACCOUNT_SERVICE_FILE_CHANGE_DIR_MODE_ERROR;
        }
        return ERR_OK;
    } while (0);
    flock(fd, LOCK_UN);
    fclose(fp);
    SetValidModifyFileOperationFlag(path, false);
    return ERR_ACCOUNT_COMMON_FILE_WRITE_FAILED;
}

ErrCode AccountFileOperator::GetFileContentByPath(const std::string &path, std::string &content)
{
    if (!IsExistFile(path)) {
        ACCOUNT_LOGE("cannot find file, path = %{public}s", path.c_str());
        return ERR_OSACCOUNT_SERVICE_FILE_FIND_FILE_ERROR;
    }
    std::shared_lock<std::shared_timed_mutex> lock(fileLock_);
    FILE *fp = fopen(path.c_str(), "rb");
    if (fp == nullptr) {
        ACCOUNT_LOGE("cannot open file %{public}s, errno %{public}d.", path.c_str(), errno);
        return ERR_ACCOUNT_COMMON_FILE_OPEN_FAILED;
    }
    int fd = fileno(fp);
    flock(fd, LOCK_SH);
    (void) fseek(fp, 0, SEEK_END);
    long fileSize = ftell(fp);
    if ((fileSize < 0) || (fileSize > MAX_FILE_SIZE)) {
        ACCOUNT_LOGE("the file(%{public}s) size is invalid, errno %{public}d.", path.c_str(), errno);
        flock(fd, LOCK_UN);
        (void) fclose(fp);
        return ERR_ACCOUNT_COMMON_FILE_READ_FAILED;
    }
    rewind(fp);
    char *buffer = new (std::nothrow) char[fileSize];
    if (buffer == nullptr) {
        ACCOUNT_LOGE("insufficient memory");
        flock(fd, LOCK_UN);
        (void) fclose(fp);
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    size_t retSize = fread(buffer, sizeof(char), fileSize, fp);
    if (static_cast<long>(retSize) != fileSize) {
        ACCOUNT_LOGE("fail to read file %{public}s", path.c_str());
        delete[] buffer;
        flock(fd, LOCK_UN);
        (void) fclose(fp);
        return ERR_ACCOUNT_COMMON_FILE_READ_FAILED;
    }
    content = std::string(buffer, retSize);
    delete[] buffer;
    flock(fd, LOCK_UN);
    (void) fclose(fp);
    return ERR_OK;
}

bool AccountFileOperator::IsExistFile(const std::string &path)
{
    if (path.empty()) {
        return false;
    }
    std::shared_lock<std::shared_timed_mutex> lock(fileLock_);
    struct stat buf = {};
    if (stat(path.c_str(), &buf) != 0) {
        ACCOUNT_LOGE("Stat %{public}s failed, errno=%{public}d.", path.c_str(), errno);
        return false;
    }

    return S_ISREG(buf.st_mode);
}

bool AccountFileOperator::IsJsonFormat(const std::string &path)
{
    std::string content;
    if (GetFileContentByPath(path, content) != ERR_OK) {
        return false;
    }

    nlohmann::json jsonData = nlohmann::json::parse(content, nullptr, false);
    if (jsonData.is_discarded() || !jsonData.is_structured()) {
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
    std::shared_lock<std::shared_timed_mutex> lock(fileLock_);
    struct stat buf = {};
    if (stat(path.c_str(), &buf) != 0) {
        ACCOUNT_LOGE("Stat %{public}s failed, errno=%{public}d", path.c_str(), errno);
        return false;
    }

    return S_ISDIR(buf.st_mode);
}
}  // namespace AccountSA
}  // namespace OHOS
