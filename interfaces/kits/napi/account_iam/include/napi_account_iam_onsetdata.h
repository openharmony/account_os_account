/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_INTERFACES_KITS_NAPI_IAM_INCLUDE_NAPI_IAM_ONSETDATA_H
#define OS_ACCOUNT_INTERFACES_KITS_NAPI_IAM_INCLUDE_NAPI_IAM_ONSETDATA_H

#include "account_error_no.h"
#include "account_iam_info.h"
#include "napi_account_common.h"

namespace OHOS {
namespace AccountJsKit {
using namespace OHOS::AccountSA;

constexpr size_t ARG_SIZE_ONE = 1;
constexpr size_t ARG_SIZE_TWO = 2;

constexpr size_t PARAM_ZERO = 0;
constexpr size_t PARAM_ONE = 1;

#ifdef HAS_PIN_AUTH_PART
struct InputerContext : public CommonAsyncContext {
    int32_t authSubType = -1;
    std::vector<uint8_t> challenge;
    std::shared_ptr<AccountSA::IInputerData> inputerData = nullptr;
    std::shared_ptr<NapiCallbackRef> callback;
};

napi_value InputDataConstructor(napi_env env, napi_callback_info info);
napi_value OnSetData(napi_env env, napi_callback_info info);
napi_value GetCtorIInputerData(napi_env env, const std::shared_ptr<AccountSA::IInputerData> &inputerData);
napi_status GetInputerInstance(InputerContext *context, napi_value *inputerDataVarCtor);
#endif // HAS_PIN_AUTH_PART
}
}
#endif // OS_ACCOUNT_INTERFACES_KITS_NAPI_IAM_INCLUDE_NAPI_IAM_ONSETDATA_H