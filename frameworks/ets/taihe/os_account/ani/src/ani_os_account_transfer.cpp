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

#include "ani_os_account_transfer.h"
#include <ani.h>
#include <array>
#include <bit>
#include <string>
#include <sys/syscall.h>
#include <unistd.h>
#include "account_log_wrapper.h"
#include "interop_js/arkts_interop_js_api.h"
#include "interop_js/arkts_esvalue.h"
#include "interop_js/arkts_interop_js_api.h"
#include "interop_js/hybridgref_ani.h"
#include "interop_js/hybridgref_napi.h"
#include "ohos.account.osAccount.impl.hpp"
#include "napi_account_iam_common.h"
#include "napi_account_iam_onsetdata.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "native_engine/native_engine.h"
#include "taihe_common.h"

using OHOS::AccountSA::ACCOUNT_LABEL;

namespace OHOS {
namespace AccountSA {
namespace {
const char *ETS_OS_ACCOUNT_TRANSFER_CLASS_NAME = "L@ohos/account/transfer/osAccount/Transfer;";
const char *OS_ACCOUNT_TAIHE_NAME_SPACE = "L@ohos/account/osAccount/osAccount;";
}

ani_object AniOsAccountTransfer::NativeIInputDataTransferStatic(ani_env *aniEnv, ani_class aniCls, ani_object input)
{
    ACCOUNT_LOGD("Transfer nativeIInputDataTransferStatic");
    if (aniEnv == nullptr) {
        ACCOUNT_LOGE("AniEnv is null");
        return nullptr;
    }

    void *unwrapResult = nullptr;
    bool success = arkts_esvalue_unwrap(aniEnv, input, &unwrapResult);
    if (!success) {
        ACCOUNT_LOGE("Failed to unwrap");
        return nullptr;
    }
    if (unwrapResult == nullptr) {
        ACCOUNT_LOGE("UnwrapResult is nullptr");
        return nullptr;
    }
#ifdef HAS_PIN_AUTH_PART
    // 1.1->1.2
    AccountJsKit::InputerContext* context = reinterpret_cast<AccountJsKit::InputerContext*>(unwrapResult);
    std::shared_ptr<AccountSA::IInputerData> inputerData = context->inputerData;
    int64_t ptr = reinterpret_cast<int64_t>(inputerData.get());
    ani_namespace ns;
    if (ANI_OK != aniEnv->FindNamespace(OS_ACCOUNT_TAIHE_NAME_SPACE, &ns)) {
        ACCOUNT_LOGE("Call findNamespace failed.");
        return nullptr;
    }
    ani_function createFunc;
    if (ANI_OK != aniEnv->Namespace_FindFunction(ns, "createIInputData", nullptr, &createFunc)) {
        ACCOUNT_LOGE("Call namespace_FindFunction failed.");
        return nullptr;
    }
    ani_ref iinputdataRef;
    if (ANI_OK != aniEnv->Function_Call_Ref(createFunc, &iinputdataRef, ptr)) {
        ACCOUNT_LOGE("Call function_Call_Ref failed.");
        return nullptr;
    }
    ani_object outObj = static_cast<ani_object>(iinputdataRef);
    return outObj;
#else
    return nullptr;
#endif
}

ani_ref AniOsAccountTransfer::GenerateDynamic(ani_env *aniEnv, int64_t ptr)
{
#ifdef HAS_PIN_AUTH_PART
    AccountSA::IInputerData* rawPtr = reinterpret_cast<AccountSA::IInputerData*>(ptr);
    auto inputerData = std::shared_ptr<AccountSA::IInputerData>(
        rawPtr,
        [](AccountSA::IInputerData *p) {
            if (p != nullptr) {
                delete p;
            }
        }
    );
    napi_env jsEnv;
    if (!arkts_napi_scope_open(aniEnv, &jsEnv)) {
        ACCOUNT_LOGE("failed to arkts_napi_scope_open");
        return nullptr;
    }
    napi_value cons = AccountJsKit::GetCtorIInputerData(jsEnv, inputerData);
    if (cons == nullptr) {
        ACCOUNT_LOGD("failed to GetCtorIInputerData");
        return nullptr;
    }
    napi_value inputerDataVarCtor;
    napi_status napiStatus = napi_new_instance(jsEnv, cons, 0, nullptr, &inputerDataVarCtor);
    if (napi_status::napi_ok != napiStatus) {
        ACCOUNT_LOGE("Failed to napi_new_instance, status=%{public}d", napiStatus);
        return nullptr;
    }
    ani_ref outObj;
    if (!arkts_napi_scope_close_n(jsEnv, 1, &inputerDataVarCtor, &outObj)) {
        ACCOUNT_LOGE("Failed to arkts_napi_scope_close_n");
        return nullptr;
    }
    return outObj;
#else
    return nullptr;
#endif
}

ani_ref AniOsAccountTransfer::NativeIInputDataTransferDynamic(ani_env *aniEnv, ani_class aniCls, ani_object input)
{
    ACCOUNT_LOGD("Transfer static NativeIInputDataTransferDynamic");
    if (aniEnv == nullptr) {
        ACCOUNT_LOGE("null aniEnv");
        return nullptr;
    }
#ifdef HAS_PIN_AUTH_PART
    // 1.2->1.1
    ani_namespace ns;
    if (ANI_OK != aniEnv->FindNamespace(OS_ACCOUNT_TAIHE_NAME_SPACE, &ns)) {
        ACCOUNT_LOGE("Call findNamespace failed.");
        return nullptr;
    }
    ani_function getFunc;
    if (ANI_OK != aniEnv->Namespace_FindFunction(ns, "getPtrByIInputData", nullptr, &getFunc)) {
        ACCOUNT_LOGE("Call namespace_FindFunction failed.");
        return nullptr;
    }
    ani_long aniPtr;
    if (ANI_OK != aniEnv->Function_Call_Long(getFunc, &aniPtr, input)) {
        ACCOUNT_LOGE("Call Function_Call_Long failed.");
        return nullptr;
    }
    int64_t ptr = static_cast<int64_t>(aniPtr);
    return GenerateDynamic(aniEnv, ptr);
#else
    return nullptr;
#endif
}

void AniOsAccountTransferInit(ani_env *aniEnv)
{
    ACCOUNT_LOGD("Init transfer native method");
    if (aniEnv == nullptr) {
        ACCOUNT_LOGE("null ani env");
        return;
    }

    ani_class cls = nullptr;
    auto status = aniEnv->FindClass(ETS_OS_ACCOUNT_TRANSFER_CLASS_NAME, &cls);
    if (status != ANI_OK) {
        ACCOUNT_LOGE("FindClass failed status: %{public}d", status);
        return;
    }

    std::array nativeStaticFuncs = {
        ani_native_function { "nativeIInputDataTransferStatic", nullptr,
            reinterpret_cast<void*>(AniOsAccountTransfer::NativeIInputDataTransferStatic)},
        ani_native_function { "nativeIInputDataTransferDynamic", nullptr,
            reinterpret_cast<void*>(AniOsAccountTransfer::NativeIInputDataTransferDynamic)},
    };
    status = aniEnv->Class_BindStaticNativeMethods(cls, nativeStaticFuncs.data(), nativeStaticFuncs.size());
    if (status != ANI_OK) {
        ACCOUNT_LOGE("Class_BindStaticNativeMethods failed status: %{public}d", status);
        return;
    }

    ACCOUNT_LOGD("Init transfer native method end");
}
}
}