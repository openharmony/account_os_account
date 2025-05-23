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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_FILE_OPERATOR_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_FILE_OPERATOR_H

#include "account_error_no.h"
#include "rwlock.h"
#include <map>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <sys/stat.h>
#include <vector>
namespace OHOS {
namespace AccountSA {
/**
 * @brief file transaction class, this class is multi-thread dangerous.
 * The status variable would be invalid in multi-thread env.
 * Read transaction is not supported
 */
class FileTransaction {
    friend class AccountFileOperator;
public:
    /**
     * @brief Init function
     * @param path file path, should be absolute path.
     * @param rwlock rwlock for this certain file.
     */
    FileTransaction(std::string path, std::shared_ptr<Utils::RWLock> &rwlock) : path_(path), rwlock_(rwlock) {};
    virtual ~FileTransaction();

    ErrCode BeginWriteTransaction();
    virtual ErrCode EndTransaction();
    ErrCode Rollback();
    void ForceUnlock();

    bool IsTempFileExist();
    static bool IsTempFileExist(const std::string &path);
    std::string GetPath() const;

protected:
    ErrCode DeleteTempFile();
    ErrCode SwapFileNames();
    ErrCode WriteFile(const std::string &content);
    ErrCode ReadFile(std::string &content);
    std::string GetTempFilePath() const;
    static std::string GetTempFilePath(const std::string &path);
private:
    void ReleaseAction();

    std::string path_;
    std::shared_ptr<Utils::RWLock> rwlock_;

    bool isOpenTransaction_ = false;
    bool isWriteSuccessOnce_ = false;
};

typedef std::shared_ptr<FileTransaction> TransactionShared;

class AccountFileOperator {
public:
    AccountFileOperator();
    virtual ~AccountFileOperator();

    ErrCode CreateDir(const std::string &path, mode_t mode = S_IRWXU);
    ErrCode DeleteDirOrFile(const std::string &path);
    ErrCode DeleteDir(const std::string &path);
    ErrCode DeleteFile(const std::string &path);
    ErrCode InputFileByPathAndContent(const std::string &path, const std::string &content);
    ErrCode GetFileContentByPath(const std::string &path, std::string &content);
    ErrCode InputFileByPathAndContentWithTransaction(const std::string &path, const std::string &content);
    bool IsExistFile(const std::string &path);
    bool IsJsonFormat(const std::string &path);
    bool IsJsonFileReady(const std::string &path);
    bool IsExistDir(const std::string &path);
    ErrCode CheckFileExistence(const std::string &path);
#ifdef ENABLE_FILE_WATCHER
    bool GetValidDeleteFileOperationFlag(const std::string &fileName);
    void SetValidDeleteFileOperationFlag(const std::string &fileName, bool flag);
    bool GetValidModifyFileOperationFlag(const std::string &fileName);
    void SetValidModifyFileOperationFlag(const std::string &fileName, bool flag);
#endif // ENABLE_FILE_WATCHER
    bool SetDirDelFlags(const std::string &dirpath);

    TransactionShared GetFileTransaction(const std::string &path);
    std::shared_ptr<Utils::RWLock> GetRWLock(const std::string &path);
public:
    mutable std::shared_timed_mutex fileLock_;

#ifdef ENABLE_FILE_WATCHER
private:
    std::vector<std::string> validModifyFileOperationFlag_;
    std::vector<std::string> validDeleteFileOperationFlag_;
#endif // ENABLE_FILE_WATCHER
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_FILE_OPERATOR_H
