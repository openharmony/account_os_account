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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_FILE_OPERATOR_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_FILE_OPERATOR_H

#include <mutex>
#include <shared_mutex>
#include <string>
#include <vector>

#include "account_error_no.h"

namespace OHOS {
namespace AccountSA {
class AccountFileOperator {
public:
    AccountFileOperator();
    virtual ~AccountFileOperator();

    ErrCode CreateDir(const std::string &path);
    ErrCode DeleteDirOrFile(const std::string &path);
    ErrCode InputFileByPathAndContent(const std::string &path, const std::string &content);
    ErrCode GetFileContentByPath(const std::string &path, std::string &content);
    bool IsExistFile(const std::string &path);
    bool IsJsonFormat(const std::string &path);
    bool IsJsonFileReady(const std::string &path);
    bool IsExistDir(const std::string &path);
    bool GetValidDeleteFileOperationFlag(const std::string &fileName);
    void SetValidDeleteFileOperationFlag(const std::string &fileName, bool flag);
    bool GetValidModifyFileOperationFlag(const std::string &fileName);
    void SetValidModifyFileOperationFlag(const std::string &fileName, bool flag);

public:
    mutable std::shared_timed_mutex fileLock_;

private:
    std::vector<std::string> validModifyFileOperationFlag_;
    std::vector<std::string> validDeleteFileOperationFlag_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_FILE_OPERATOR_H
