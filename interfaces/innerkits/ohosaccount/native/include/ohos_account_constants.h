/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OHOSACCOUNT_ACCOUNT_CONSTANTS_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OHOSACCOUNT_ACCOUNT_CONSTANTS_H

#include "account_error_no.h"

namespace OHOS {
namespace AccountSA {
namespace Constants {
constexpr std::size_t NICKNAME_MAX_SIZE = 1024;
constexpr std::size_t AVATAR_MAX_SIZE = 10 * 1024 * 1024;
constexpr std::size_t SCALABLEDATA_MAX_SIZE = 1024;
};  // namespace Constants
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_CONSTANTS_H
