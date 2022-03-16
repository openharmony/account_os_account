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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_TEST_MOCK_OS_ACCOUNT_PERMISSION_KIT_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_TEST_MOCK_OS_ACCOUNT_PERMISSION_KIT_H

#include <string>
#include "account_error_no.h"

namespace OHOS {
namespace Security {
namespace Permission {
typedef enum TypePermissionState {
    PERMISSION_NOT_GRANTED = -1,
    PERMISSION_GRANTED = 0,
} PermissionState;

class PermissionKit {
public:
    static ErrCode VerifyPermission(const std::string &permissionName);
};
}  // namespace Permission
}  // namespace Security
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_TEST_MOCK_OS_ACCOUNT_PERMISSION_KIT_H
