/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_FILE_WATCHER_MANAGER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_FILE_WATCHER_MANAGER_H

#include <mutex>
#include <sys/inotify.h>
#include <sys/time.h>
#include "account_error_no.h"
#include "account_file_operator.h"
#include "singleton.h"

namespace OHOS {
namespace AccountSA {
int32_t GenerateAccountInfoDigest(const std::string &inData, uint8_t* outData, uint32_t size);

using CheckNotifyEventCallbackFunc = std::function<bool(const std::string&, const int32_t, uint32_t)>;
class FileWatcher {
public:
    FileWatcher(const int32_t id);
    FileWatcher(const std::string &filePath);
    ~FileWatcher();

    std::string GetFilePath();
    int32_t GetLocalId();
    int32_t GetWd();

    bool StartNotify(const int32_t fd, const uint32_t &watchEvents);
    void CloseNotify(int32_t fd);
    bool CheckNotifyEvent(uint32_t event);
    void SetEventCallback(CheckNotifyEventCallbackFunc &func);

public:
    int32_t id_ = -1;

private:
    int32_t wd_ = -1; // generate from inotify_add_watch
    std::string filePath_;
    CheckNotifyEventCallbackFunc eventCallbackFunc_;
};

class AccountFileWatcherMgr {
public:
    static AccountFileWatcherMgr &GetInstance();
    void StartWatch();
    void AddFileWatcher(
        const int32_t id, CheckNotifyEventCallbackFunc checkCallbackFunc, const std::string filePath = "");
    void RemoveFileWatcher(const int32_t id, const std::string filePath);
    ErrCode GetAccountInfoDigestFromFile(const std::string &path, uint8_t *digest, uint32_t size);
    ErrCode GenerateAccountInfoDigestStr(
        const std::string &userInfoPath, const std::string &accountInfoStr, std::string &digestStr);
    ErrCode AddAccountInfoDigest(const std::string accountInfo, const std::string &userInfoPath);
    ErrCode DeleteAccountInfoDigest(const std::string &userInfoPath);

private:
    void DealWithFileEvent();
    void GetNotifyEvent();
    AccountFileWatcherMgr();
    ~AccountFileWatcherMgr();
    DISALLOW_COPY_AND_MOVE(AccountFileWatcherMgr);

public:
    int32_t inotifyFd_ = -1;

    std::mutex accountInfoDigestFileLock_;
    std::mutex fileWatcherMgrLock_;
    std::shared_ptr<AccountFileOperator> accountFileOperator_;
    std::unordered_map<int32_t, std::shared_ptr<FileWatcher>> fileNameMgrMap_;
    fd_set fds_;
    bool run_ = false;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_CONTROL_FILE_MANAGER_H
