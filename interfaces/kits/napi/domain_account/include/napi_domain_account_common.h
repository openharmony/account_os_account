/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_INTERFACES_KITS_COMMON_INCLUDE_NAPI_ACCOUNT_DOMAIN_COMMON_H
#define OS_ACCOUNT_INTERFACES_KITS_COMMON_INCLUDE_NAPI_ACCOUNT_DOMAIN_COMMON_H

#include <mutex>
#include <string>
#include <vector>
#include <uv.h>

#include "account_error_no.h"
#include "napi/native_api.h"
#include "domain_account_common.h"

namespace OHOS {
namespace AccountJsKit {
using namespace AccountSA;
bool ParseDomainAccountInfo(napi_env env, napi_value object, DomainAccountInfo &info);
} // namespace AccountJsKit
} // namespace OHOS

#endif // OS_ACCOUNT_INTERFACES_KITS_COMMON_INCLUDE_NAPI_ACCOUNT_DOMAIN_COMMON_H
