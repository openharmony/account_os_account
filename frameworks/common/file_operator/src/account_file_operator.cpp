/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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
#include <fcntl.h>
#include <fstream>
#include <nlohmann/json.hpp>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>
#include "account_log_wrapper.h"
#include "directory_ex.h"
#include "account_hisysevent_adapter.h"
namespace OHOS {
namespace AccountSA {
namespace {
#ifdef ENABLE_FILE_WATCHER
constexpr char ACCOUNT_INFO_DIGEST_FILE_PATH[] = "account_info_digest.json";
#endif // ENABLE_FILE_WATCHER
const long MAX_FILE_SIZE = 16 * 1024 * 1024; // 16MB
const unsigned long long BUFF_FILE_SIZE = 50 * 1024 * 1024; // 50MB
const uint32_t RETRY_TIMES = 3;
const uint32_t RETRY_SLEEP_MS = 5;
#define HMFS_MONITOR_FL 0x00000002
#define HMFS_IOCTL_HW_GET_FLAGS _IOR(0XF5, 70, unsigned int)
#define HMFS_IOCTL_HW_SET_FLAGS _IOR(0XF5, 71, unsigned int)
const uint64_t FDSAN_DIR_TAG = fdsan_create_owner_tag(FDSAN_OWNER_TYPE_DIRECTORY, 0xC01B00);
static std::map<std::string, std::shared_ptr<Utils::RWLock>> RWLOCK_MAP;
static std::mutex RWLOCK_MAP_MUTEX;
const char OPERATION_LOG_ERROR[] = "errLog";
const int32_t RELEASE_COUNT = 2;
} // namespace

static bool FileExists(const std::string &path)
{
    uint32_t retryCount = 0;
    while (retryCount < RETRY_TIMES) {
        struct stat buf = {};
        if (stat(path.c_str(), &buf) == 0) {
            return S_ISREG(buf.st_mode);
        }
        if (errno != ENOENT) {
            ACCOUNT_LOGE("Stat %{public}s failed, errno=%{public}d. Retrying...", path.c_str(), errno);
            std::this_thread::sleep_for(std::chrono::milliseconds(RETRY_SLEEP_MS));
            retryCount++;
        } else {
            return false;
        }
    }
    std::string errMsg = "Stat " + path + " with retry failed.";
    REPORT_OS_ACCOUNT_FAIL(0, OPERATION_LOG_ERROR, ENOENT, errMsg);
    return false;
}

FileTransaction::~FileTransaction()
{
    ReleaseAction();
}

static void TryEraseTransaction(const std::string &path)
{
    std::lock_guard<std::mutex> lock(RWLOCK_MAP_MUTEX);
    auto iter = RWLOCK_MAP.find(path);
    if (iter == RWLOCK_MAP.end()) {
        return;
    }
    // if count == 2, it is only handled by map and one transaction. need release.
    if (iter->second.use_count() == RELEASE_COUNT) {
        RWLOCK_MAP.erase(iter);
    }
}

ErrCode FileTransaction::BeginWriteTransaction()
{
    if (isOpenTransaction_) {
        ACCOUNT_LOGE("Transaction already started.");
        return ERR_ACCOUNT_COMMON_FILE_TRANSACTION_FAILED;
    }
    rwlock_->LockWrite();
    isOpenTransaction_ = true;
    std::string tempFilePath = GetTempFilePath();
    std::string folderPath = tempFilePath.substr(0, tempFilePath.rfind('/'));
    AccountFileOperator tempFileOperator;
    if (!tempFileOperator.IsExistDir(folderPath)) {
        ErrCode errCode = tempFileOperator.CreateDir(folderPath);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("Failed to create dir, str = %{public}s errCode %{public}d.", folderPath.c_str(), errCode);
            rwlock_->UnLockWrite();
            return errCode;
        }
    }
    FILE *tempFile = fopen(tempFilePath.c_str(), "wb");
    if (tempFile == nullptr) {
        ACCOUNT_LOGE("Failed to open %{public}s, errno %{public}d.", tempFilePath.c_str(), errno);
        rwlock_->UnLockWrite();
        return ERR_ACCOUNT_COMMON_FILE_OPEN_FAILED;
    }
    (void)fclose(tempFile);
    return ERR_OK;
}

void FileTransaction::ForceUnlock()
{
    if (!isOpenTransaction_) {
        ACCOUNT_LOGE("Transaction not started.");
        return;
    }
    rwlock_->UnLockWrite();
    isOpenTransaction_ = false;
    return;
}

ErrCode FileTransaction::Rollback()
{
    if (!isOpenTransaction_) {
        return ERR_OK;
    }
    ErrCode ret = DeleteTempFile();
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Delete temp file failed, ret = %{public}d.", ret);
    }
    ForceUnlock();
    return ret;
}

ErrCode FileTransaction::EndTransaction()
{
    if (!isOpenTransaction_) {
        return ERR_OK;
    }
    if (isWriteSuccessOnce_) {
        ErrCode ret = SwapFileNames();
        if (ret != ERR_OK) {
            ACCOUNT_LOGE("SwapFileNames failed.");
            return ret;
        }
    }
    // if file delete not ok, return ok, write is success.
    ErrCode ret = DeleteTempFile();
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Delete temp file failed, ret = %{public}d.", ret);
        return ret;
    }
    ForceUnlock();
    return ERR_OK;
}

static ErrCode WriteFile(const std::string &path, const std::string &content)
{
    FILE *fp = fopen(path.c_str(), "wb");
    if (fp == nullptr) {
        ACCOUNT_LOGE("Failed to open %{public}s, errno = %{public}d.", path.c_str(), errno);
        return ERR_ACCOUNT_COMMON_FILE_OPEN_FAILED;
    }
    int fd = fileno(fp);
    do {
        flock(fd, LOCK_EX);
        size_t num = fwrite(content.c_str(), sizeof(char), content.length(), fp);
        if (num != content.length()) {
            ACCOUNT_LOGE("Failed to fwrite %{public}s, errno = %{public}d.", path.c_str(), errno);
            break;
        }
        if (fflush(fp) != 0) {
            ACCOUNT_LOGE("Failed to fflush %{public}s, errno = %{public}d.", path.c_str(), errno);
            break;
        }
        if (fsync(fd) != 0) {
            ACCOUNT_LOGE("Failed to fsync %{public}s, errno = %{public}d.", path.c_str(), errno);
            break;
        }
        flock(fd, LOCK_UN);
        (void)fclose(fp);
        // change mode
        if (!ChangeModeFile(path, S_IRUSR | S_IWUSR)) {
            ACCOUNT_LOGW("Failed to change mode for file %{public}s, errno = %{public}d.", path.c_str(), errno);
            return ERR_OHOSACCOUNT_SERVICE_FILE_CHANGE_DIR_MODE_ERROR;
        }
        return ERR_OK;
    } while (0);
    flock(fd, LOCK_UN);
    (void)fclose(fp);
    return ERR_ACCOUNT_COMMON_FILE_WRITE_FAILED;
}

ErrCode FileTransaction::WriteFile(const std::string &content)
{
    if (!isOpenTransaction_) {
        ACCOUNT_LOGE("Transaction not started.");
        return ERR_ACCOUNT_COMMON_FILE_WRITE_FAILED;
    }
    std::string tempFilePath = GetTempFilePath();
    ErrCode err = AccountSA::WriteFile(tempFilePath, content);
    if (err != ERR_OK) {
        ACCOUNT_LOGE("Write file failed.");
        return ERR_ACCOUNT_COMMON_FILE_WRITE_FAILED;
    }
    isWriteSuccessOnce_ = true;
    return ERR_OK;
}

static ErrCode ReadFile(const std::string &path, std::string &content)
{
    if (!FileExists(path)) {
        ACCOUNT_LOGE("cannot find file, path = %{public}s", path.c_str());
        return ERR_OSACCOUNT_SERVICE_FILE_FIND_FILE_ERROR;
    }
    FILE *fp = fopen(path.c_str(), "rb");
    if (fp == nullptr) {
        ACCOUNT_LOGE("Cannot open file %{public}s, errno %{public}d.", path.c_str(), errno);
        return ERR_ACCOUNT_COMMON_FILE_OPEN_FAILED;
    }
    int fd = fileno(fp);
    flock(fd, LOCK_SH);
    (void)fseek(fp, 0, SEEK_END);
    long fileSize = ftell(fp);
    if ((fileSize < 0) || (fileSize > MAX_FILE_SIZE)) {
        ACCOUNT_LOGE("The file(%{public}s) size is invalid, errno %{public}d.", path.c_str(), errno);
        flock(fd, LOCK_UN);
        (void)fclose(fp);
        return ERR_ACCOUNT_COMMON_FILE_READ_FAILED;
    }
    rewind(fp);
    std::unique_ptr<char[]> buffer = std::make_unique<char[]>(fileSize);
    size_t retSize = fread(buffer.get(), sizeof(char), fileSize, fp);
    if (static_cast<long>(retSize) != fileSize) {
        ACCOUNT_LOGE("Fail to read file %{public}s", path.c_str());
        flock(fd, LOCK_UN);
        (void)fclose(fp);
        return ERR_ACCOUNT_COMMON_FILE_READ_FAILED;
    }
    content = std::string(buffer.get(), retSize);
    flock(fd, LOCK_UN);
    (void)fclose(fp);
    return ERR_OK;
}

ErrCode FileTransaction::ReadFile(std::string &content)
{
    return AccountSA::ReadFile(path_, content);
}

bool FileTransaction::IsTempFileExist()
{
    return FileExists(GetTempFilePath());
}

bool FileTransaction::IsTempFileExist(const std::string &path)
{
    return FileExists(GetTempFilePath(path));
}

ErrCode FileTransaction::DeleteTempFile()
{
    bool delFlag = false;
    std::string tempFilePath = GetTempFilePath();
    uint32_t i = 0;
    do {
        delFlag = OHOS::RemoveFile(tempFilePath);
        if (delFlag) {
            break;
        }
        i++;
        std::this_thread::sleep_for(std::chrono::milliseconds(RETRY_SLEEP_MS));
    } while (i <= RETRY_TIMES);
    if (!delFlag) {
        int32_t err = errno;
        ACCOUNT_LOGE("DeleteTempFile failed, path %{public}s, errno %{public}d.", tempFilePath.c_str(), err);
        std::string errMsg = "DeleteTempFile failed, path " + tempFilePath + ", errno " + std::to_string(err);
        REPORT_OS_ACCOUNT_FAIL(0, OPERATION_LOG_ERROR, err, errMsg);
        return ERR_OSACCOUNT_SERVICE_FILE_DELE_ERROR;
    }
    return ERR_OK;
}

std::string FileTransaction::GetTempFilePath(const std::string &path)
{
    return path + ".tmp";
}

std::string FileTransaction::GetTempFilePath() const
{
    return GetTempFilePath(path_);
}

ErrCode FileTransaction::SwapFileNames()
{
    std::string tempFileName = GetTempFilePath();

    bool isTempFileExist = FileExists(tempFileName);
    if (!isTempFileExist) {
        ACCOUNT_LOGI("Temp file does not exist, path = %{public}s.", tempFileName.c_str());
        return ERR_OK;
    }
    bool isTargetFileExist = FileExists(path_);
    uint32_t mode = RENAME_NOREPLACE;
    if (isTargetFileExist) {
        if (!ChangeModeFile(path_, S_IRUSR | S_IWUSR)) {
            ACCOUNT_LOGW("Failed to change mode for file %{public}s, errno = %{public}d.", path_.c_str(), errno);
            return ERR_OHOSACCOUNT_SERVICE_FILE_CHANGE_DIR_MODE_ERROR;
        }
        mode = RENAME_EXCHANGE;
    }
    for (uint32_t i = 0; i <= RETRY_TIMES; i++) {
        int32_t ret = renameat2(AT_FDCWD, tempFileName.c_str(), 0, path_.c_str(), mode);
        if (ret == ERR_OK) {
            return ERR_OK;
        }
        if ((ret != ERR_OK) && (errno != EAGAIN)) {
            int32_t err = errno;
            ACCOUNT_LOGE("Failed to swap file names, errno = %{public}d, errMsg = %{public}s", err, strerror(err));
            std::string errMsg = "Failed to swap file " + tempFileName + " and " +
                path_ + ", errMsg = %{public}s" + strerror(err);
            REPORT_OS_ACCOUNT_FAIL(0, OPERATION_LOG_ERROR, err, errMsg);
            return ERR_ACCOUNT_COMMON_FILE_SWAP_FAILED;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(RETRY_SLEEP_MS));
    }
    std::string errMsg =
        "Failed to swap file " + tempFileName + " and " + path_ + ", with retry";
    REPORT_OS_ACCOUNT_FAIL(0, OPERATION_LOG_ERROR, EAGAIN, errMsg);
    return ERR_ACCOUNT_COMMON_FILE_SWAP_FAILED;
}

void FileTransaction::ReleaseAction()
{
    if (isOpenTransaction_) {
        this->Rollback();
    }
    TryEraseTransaction(path_);
    rwlock_ = nullptr;
}

std::string FileTransaction::GetPath() const
{
    return path_;
}

AccountFileOperator::AccountFileOperator() {}

AccountFileOperator::~AccountFileOperator() {}

ErrCode AccountFileOperator::CreateDir(const std::string &path, mode_t mode)
{
    ACCOUNT_LOGI("Start creating a directory");
    std::unique_lock<std::shared_timed_mutex> lock(fileLock_);
    if (!OHOS::ForceCreateDirectory(path)) {
        ACCOUNT_LOGE("failed to create %{public}s, errno %{public}d.", path.c_str(), errno);
        return ERR_OSACCOUNT_SERVICE_FILE_CREATE_DIR_ERROR;
    }
    SetDirDelFlags(path);
    bool createFlag = OHOS::ChangeModeDirectory(path, mode);
    if (!createFlag) {
        ACCOUNT_LOGE("failed to change mode for %{public}s, errno %{public}d.", path.c_str(), errno);
        return ERR_OSACCOUNT_SERVICE_FILE_CHANGE_DIR_MODE_ERROR;
    }

    return ERR_OK;
}

ErrCode AccountFileOperator::DeleteDirOrFile(const std::string &path)
{
    if (IsExistDir(path)) {
        return DeleteDir(path);
    }
    if (IsExistFile(path)) {
        return DeleteFile(path);
    }
    ACCOUNT_LOGI("Dir or file does not exist, path %{public}s.", path.c_str());
    return ERR_OK;
}

ErrCode AccountFileOperator::DeleteDir(const std::string &path)
{
    std::unique_lock<std::shared_timed_mutex> lock(fileLock_);
    bool delFlag = false;
    delFlag = OHOS::ForceRemoveDirectory(path);
    if (!delFlag) {
        ACCOUNT_LOGE("DeleteDirOrFile failed, path %{public}s errno %{public}d.", path.c_str(), errno);
        return ERR_OSACCOUNT_SERVICE_FILE_DELE_ERROR;
    }
#ifdef ENABLE_FILE_WATCHER
    SetValidDeleteFileOperationFlag(path, true);
#endif // ENABLE_FILE_WATCHER
    return ERR_OK;
}

ErrCode AccountFileOperator::DeleteFile(const std::string &path)
{
    std::unique_lock<std::shared_timed_mutex> lock(fileLock_);
    bool delFlag = false;
    delFlag = OHOS::RemoveFile(path);
    if (!delFlag) {
        ACCOUNT_LOGE("DeleteDirOrFile failed, path %{public}s errno %{public}d.", path.c_str(), errno);
        return ERR_OSACCOUNT_SERVICE_FILE_DELE_ERROR;
    }
#ifdef ENABLE_FILE_WATCHER
    SetValidDeleteFileOperationFlag(path, true);
#endif // ENABLE_FILE_WATCHER
    return ERR_OK;
}

#ifdef ENABLE_FILE_WATCHER
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
#endif // ENABLE_FILE_WATCHER

static bool IsDataStorageSufficient(const unsigned long long reqFreeBytes)
{
    struct statvfs diskInfo;
    int ret = statvfs("/data", &diskInfo);
    if (ret != 0) {
        ACCOUNT_LOGE("Get disk info failed, ret=%{public}d, errno=%{public}d.", ret, errno);
        return false;
    }

    unsigned long long freeBytes =
        static_cast<unsigned long long>(diskInfo.f_bsize) * static_cast<unsigned long long>(diskInfo.f_bavail);
    bool isSufficient = (freeBytes > reqFreeBytes + BUFF_FILE_SIZE);
    if (!isSufficient) {
        ACCOUNT_LOGE("Data storage is insufficient, freeBytes=%{public}llu, reqFreeBytes=%{public}llu.", freeBytes,
                     reqFreeBytes);
    }
    return isSufficient;
}

bool AccountFileOperator::SetDirDelFlags(const std::string &dirpath)
{
    char realPath[PATH_MAX] = {0};
    if (realpath(dirpath.c_str(), realPath) == nullptr) {
        ACCOUNT_LOGE("Failed to get realpath");
        return false;
    }
    int32_t fd = open(realPath, O_DIRECTORY);
    if (fd < 0) {
        ACCOUNT_LOGE("Failed to open dir, errno: %{public}d", errno);
        return false;
    }
    fdsan_exchange_owner_tag(fd, 0, FDSAN_DIR_TAG);
    unsigned int flags = 0;
    int32_t ret = ioctl(fd, HMFS_IOCTL_HW_GET_FLAGS, &flags);
    if (ret < 0) {
        fdsan_close_with_tag(fd, FDSAN_DIR_TAG);
        ACCOUNT_LOGE("Failed to get flags, errno: %{public}d", errno);
        return false;
    }
    if (flags & HMFS_MONITOR_FL) {
        fdsan_close_with_tag(fd, FDSAN_DIR_TAG);
        ACCOUNT_LOGE("Delete control flag is already set");
        return false;
    }
    flags |= HMFS_MONITOR_FL;
    ret = ioctl(fd, HMFS_IOCTL_HW_SET_FLAGS, &flags);
    if (ret < 0) {
        fdsan_close_with_tag(fd, FDSAN_DIR_TAG);
        ACCOUNT_LOGE("Failed to set flags, errno: %{public}d", errno);
        return false;
    }
    fdsan_close_with_tag(fd, FDSAN_DIR_TAG);
    return true;
}

ErrCode AccountFileOperator::InputFileByPathAndContentWithTransaction(
    const std::string &path, const std::string &content)
{
    if (!IsDataStorageSufficient(content.length())) {
        return ERR_ACCOUNT_COMMON_DATA_NO_SPACE;
    }
    std::unique_lock<std::shared_timed_mutex> lock(fileLock_);
    auto transaction = GetFileTransaction(path);
    if (transaction == nullptr) {
        ACCOUNT_LOGE("GetFileTransaction failed, get nullptr.");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    ErrCode errCode = transaction->BeginWriteTransaction();
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("BeginWriteTransaction failed, result = %{public}d", errCode);
        return errCode;
    }
    errCode = transaction->WriteFile(content);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("WriteFile failed, result = %{public}d", errCode);
        return errCode;
    }
    errCode = transaction->EndTransaction();
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("EndTransaction failed, result = %{public}d", errCode);
    }
    return errCode;
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
    if (!IsDataStorageSufficient(content.length())) {
        return ERR_ACCOUNT_COMMON_DATA_NO_SPACE;
    }
    std::unique_lock<std::shared_timed_mutex> lock(fileLock_);
#ifdef ENABLE_FILE_WATCHER
    SetValidModifyFileOperationFlag(path, true);
#endif // ENABLE_FILE_WATCHER
    ErrCode ret = WriteFile(path, content);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("WriteFile failed, path = %{public}s.", path.c_str());
#ifdef ENABLE_FILE_WATCHER
        SetValidModifyFileOperationFlag(path, false);
#endif // ENABLE_FILE_WATCHER
    }
    return ret;
}

ErrCode AccountFileOperator::GetFileContentByPath(const std::string &path, std::string &content)
{
    if (!IsExistFile(path)) {
        ACCOUNT_LOGE("cannot find file, path = %{public}s", path.c_str());
        return ERR_OSACCOUNT_SERVICE_FILE_FIND_FILE_ERROR;
    }
    std::shared_lock<std::shared_timed_mutex> lock(fileLock_);
    ErrCode ret = ReadFile(path, content);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Failed to read file, path = %{public}s, ret = %{public}d", path.c_str(), ret);
    }
    return ret;
}

bool AccountFileOperator::IsExistFile(const std::string &path)
{
    if (path.empty()) {
        ACCOUNT_LOGE("Path is empty.");
        return false;
    }
    std::shared_lock<std::shared_timed_mutex> lock(fileLock_);
    return FileExists(path);
}

ErrCode AccountFileOperator::CheckFileExistence(const std::string &path)
{
    if (path.empty()) {
        ACCOUNT_LOGE("Path is empty.");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    std::shared_lock<std::shared_timed_mutex> lock(fileLock_);
    uint32_t retryCount = 0;
    while (retryCount < RETRY_TIMES) {
        struct stat buf = {};
        if (stat(path.c_str(), &buf) == 0) {
            if (S_ISREG(buf.st_mode)) {
                return ERR_OK;
            }
            ACCOUNT_LOGE("S_ISREG failed, errno=%{public}d.", errno);
            return ERR_ACCOUNT_COMMON_FILE_OTHER_ERROR;
        }
        if (errno != ENOENT) {
            ACCOUNT_LOGE("Stat %{public}s failed, errno=%{public}d. Retrying...", path.c_str(), errno);
            std::this_thread::sleep_for(std::chrono::milliseconds(RETRY_SLEEP_MS));
            retryCount++;
        } else {
            ACCOUNT_LOGE("Stat %{public}s failed, errno=%{public}d.", path.c_str(), errno);
            return ERR_ACCOUNT_COMMON_FILE_NOT_EXIST;
        }
    }
    return ERR_ACCOUNT_COMMON_FILE_OTHER_ERROR;
}

bool AccountFileOperator::IsJsonFormat(const std::string &path)
{
    std::string content;
    if (GetFileContentByPath(path, content) != ERR_OK) {
        return false;
    }

    nlohmann::json jsonData = nlohmann::json::parse(content, nullptr, false);
    if (jsonData.is_discarded() || !jsonData.is_structured()) {
        ACCOUNT_LOGE("File %{public}s is invalid json format, size: %{public}zu", path.c_str(), content.size());
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

TransactionShared AccountFileOperator::GetFileTransaction(const std::string &path)
{
    auto shared_lock = GetRWLock(path);
    auto ret = std::make_shared<FileTransaction>(path, shared_lock);
    return ret;
}

std::shared_ptr<Utils::RWLock> AccountFileOperator::GetRWLock(const std::string &path)
{
    std::lock_guard<std::mutex> lock(RWLOCK_MAP_MUTEX);
    auto iter = RWLOCK_MAP.find(path);
    if (iter != RWLOCK_MAP.end()) {
        return iter->second;
    }
    std::shared_ptr<Utils::RWLock> rwlock = std::make_shared<Utils::RWLock>();
    RWLOCK_MAP.emplace(path, rwlock);
    return rwlock;
}
} // namespace AccountSA
} // namespace OHOS
