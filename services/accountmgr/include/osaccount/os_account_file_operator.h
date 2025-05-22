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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_INNER_OS_ACCOUNT_FILE_OPERATOR_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_INNER_OS_ACCOUNT_FILE_OPERATOR_H

#include <memory>
#include "account_file_operator.h"
#include "iaccount_info.h"
#include "json_utils.h"

namespace OHOS {
namespace AccountSA {
class OsAccountFileOperator {
public:
    OsAccountFileOperator();
    ~OsAccountFileOperator();
    ErrCode GetConstraintsByType(const int type, std::vector<std::string> &constraints);
    ErrCode GetIsMultiOsAccountEnable(bool &isMultiOsAccountEnable);
    bool CheckConstraints(const std::vector<std::string> &constraints);
    ErrCode IsAllowedCreateAdmin(bool &isAllowedCreateAdmin);
    ErrCode GetBaseOAConstraintsList(const int32_t id, std::vector<std::string> &constraints);
    ErrCode GetGlobalOAConstraintsList(std::vector<std::string> &constraints);
    ErrCode GetSpecificOAConstraintsList(const int32_t id, std::vector<std::string> &constraints);

private:
    std::shared_ptr<AccountFileOperator> accountFileOperator_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_INNER_OS_ACCOUNT_FILE_OPERATOR_H