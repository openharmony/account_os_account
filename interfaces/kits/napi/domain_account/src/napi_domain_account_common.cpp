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

#include "napi_domain_account_common.h"

#include "account_log_wrapper.h"
#include "napi_account_common.h"
#include "napi/native_common.h"

namespace OHOS {
namespace AccountJsKit {
using namespace AccountSA;
bool ParseDomainAccountInfo(napi_env env, napi_value object, DomainAccountInfo &info)
{
    napi_valuetype type = napi_undefined;
    napi_typeof(env, object, &type);
    if (type != napi_object) {
        ACCOUNT_LOGE("Value is not an object.");
        return false;
    }
    if (!GetStringPropertyByKey(env, object, "domain", info.domain_)) {
        ACCOUNT_LOGE("Get domainInfo's domain failed");
        return false;
    }
    if (!GetStringPropertyByKey(env, object, "accountName", info.accountName_)) {
        ACCOUNT_LOGE("Get domainInfo's accountName failed");
        return false;
    }
    if (!GetOptionalStringPropertyByKey(env, object, "accountId", info.accountId_)) {
        ACCOUNT_LOGE("Get domainInfo's accountId failed");
        return false;
    }
    if (!GetOptionalStringPropertyByKey(env, object, "serverConfigId", info.serverConfigId_)) {
        ACCOUNT_LOGE("Get domainInfo's serverConfigId failed");
        return false;
    }
    return true;
}
} // namespace AccountJsKit
} // namespace OHOS