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

#include "ani_app_account_transfer.h"
#include <ani.h>
#include <array>
#include <bit>
#include <string>
#include <sys/syscall.h>
#include <unistd.h>
#include "account_log_wrapper.h"
#include "app_account_manager.h"
#include "interop_js/arkts_esvalue.h"
#include "interop_js/arkts_interop_js_api.h"
#include "interop_js/hybridgref_ani.h"
#include "interop_js/hybridgref_napi.h"
#include "ohos.account.appAccount.impl.hpp"
#include "napi_app_account.h"
#include "napi_app_account_authenticator_callback.h"
#include "napi_app_account_transfer.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "native_engine/native_engine.h"

using OHOS::AccountSA::ACCOUNT_LABEL;

namespace OHOS {
namespace AccountSA {
namespace {
const char *ETS_APP_ACCOUNT_TRANSFER_CLASS_NAME = "L@ohos/appAccount/transfer/appAccount/Transfer;";
const char *APP_ACCOUNT_TAIHE_NAME_SPACE = "L@ohos/account/appAccount/appAccount;";
}
const std::string APP_ACCOUNT_CLASS_NAME = "AppAccountManager";

ani_object AniAppAccountTransfer::NativeAppAccountManagerTransferStatic(ani_env *aniEnv,
    ani_class aniCls, ani_object input)
{
    ACCOUNT_LOGD("Transfer NativeAppAccountManagerTransferStatic");
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
    // 1.1->1.2
    OHOS::AccountSA::AppAccountManager* data = reinterpret_cast<OHOS::AccountSA::AppAccountManager*>(unwrapResult);
    uint64_t appAccountManagerHandle = reinterpret_cast<uint64_t>(data);
    ani_namespace ns;
    if (ANI_OK != aniEnv->FindNamespace(APP_ACCOUNT_TAIHE_NAME_SPACE, &ns)) {
        ACCOUNT_LOGE("Call findNamespace failed.");
        return nullptr;
    }
    ani_function createFunc;
    if (ANI_OK != aniEnv->Namespace_FindFunction(ns, "createAppAccountManagerByPtr", nullptr, &createFunc)) {
        ACCOUNT_LOGE("Call namespace_FindFunction failed.");
        return nullptr;
    }
    ani_ref managerRef;
    if (ANI_OK != aniEnv->Function_Call_Ref(createFunc, &managerRef, appAccountManagerHandle)) {
        ACCOUNT_LOGE("Call function_Call_Ref failed.");
        return nullptr;
    }
    ani_object outObj = static_cast<ani_object>(managerRef);
    return outObj;
}

napi_value AniAppAccountTransfer::JsConstructor(napi_env env, napi_callback_info cbInfo)
{
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, cbInfo, nullptr, nullptr, &thisVar, nullptr));
    return thisVar;
}

ani_ref AniAppAccountTransfer::GenerateAppAccountMangerDynamic(ani_env *aniEnv, uint64_t ptr)
{
    OHOS::AccountSA::AppAccountManager* rawPtr = reinterpret_cast<OHOS::AccountSA::AppAccountManager*>(ptr);

    napi_env jsEnv;
    if (!arkts_napi_scope_open(aniEnv, &jsEnv)) {
        ACCOUNT_LOGE("failed to arkts_napi_scope_open");
        return nullptr;
    }

    napi_value cons = nullptr;
    napi_define_class(jsEnv, APP_ACCOUNT_CLASS_NAME.c_str(), APP_ACCOUNT_CLASS_NAME.size(), JsConstructor, nullptr,
        AccountJsKit::NapiAppAccount::GetPropertySize(), AccountJsKit::NapiAppAccount::appAccountProperties, &cons);
    napi_value instance = nullptr;
    if (napi_new_instance(jsEnv, cons, 0, nullptr, &instance) != napi_ok) {
        return nullptr;
    }
    napi_status status = napi_wrap(jsEnv, instance, rawPtr,
        [](napi_env jsEnv, void *data, void *hint) {
            ACCOUNT_LOGI("js AppAccountManager instance garbage collection");
            delete reinterpret_cast<AccountSA::AppAccountManager *>(data);
        }, nullptr, nullptr);
    if (status != napi_ok) {
        ACCOUNT_LOGE("failed to wrap js instance with native object");
        return nullptr;
    }
    ani_ref outObj;
    if (!arkts_napi_scope_close_n(jsEnv, 1, &instance, &outObj)) {
        ACCOUNT_LOGE("Failed to arkts_napi_scope_close_n");
        return nullptr;
    }
    return outObj;
}

ani_ref AniAppAccountTransfer::NativeAppAccountManagerTransferDynamic(ani_env *aniEnv,
    ani_class aniCls, ani_object input)
{
    ACCOUNT_LOGD("Transfer NativeAppAccountManagerTransferDynamic");
    if (aniEnv == nullptr) {
        ACCOUNT_LOGE("null aniEnv");
        return nullptr;
    }
    // 1.2->1.1
    ani_namespace ns;
    if (ANI_OK != aniEnv->FindNamespace(APP_ACCOUNT_TAIHE_NAME_SPACE, &ns)) {
        ACCOUNT_LOGE("Call findNamespace failed.");
        return nullptr;
    }
    ani_function getFunc;
    if (ANI_OK != aniEnv->Namespace_FindFunction(ns, "getPtrByAppAccountManager", nullptr, &getFunc)) {
        ACCOUNT_LOGE("Call namespace_FindFunction failed.");
        return nullptr;
    }
    ani_long aniPtr;
    if (ANI_OK != aniEnv->Function_Call_Long(getFunc, &aniPtr, input)) {
        ACCOUNT_LOGE("Call Function_Call_Long failed.");
        return nullptr;
    }
    uint64_t ptr = static_cast<uint64_t>(aniPtr);
    return GenerateAppAccountMangerDynamic(aniEnv, ptr);
}

ani_object AniAppAccountTransfer::NativeAuthCallbackTransferStatic(ani_env *aniEnv, ani_class aniCls, ani_object input)
{
    ACCOUNT_LOGD("Transfer NativeAuthCallbackTransferStatic");
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
    // 1.1->1.2
    OHOS::AccountJsKit::NapiAppAccountAuthenticatorCallback* data =
        reinterpret_cast<OHOS::AccountJsKit::NapiAppAccountAuthenticatorCallback*>(unwrapResult);
    uint64_t callbackHandle = reinterpret_cast<uint64_t>(data->GetRemoteObject().GetRefPtr());
    ani_namespace ns;
    if (ANI_OK != aniEnv->FindNamespace(APP_ACCOUNT_TAIHE_NAME_SPACE, &ns)) {
        ACCOUNT_LOGE("Call findNamespace failed.");
        return nullptr;
    }
    ani_function createFunc;
    if (ANI_OK != aniEnv->Namespace_FindFunction(ns, "getAuthCallbackByPtr", nullptr, &createFunc)) {
        ACCOUNT_LOGE("Call namespace_FindFunction failed.");
        return nullptr;
    }
    ani_ref callbackRef;
    if (ANI_OK != aniEnv->Function_Call_Ref(createFunc, &callbackRef, callbackHandle)) {
        ACCOUNT_LOGE("Call function_Call_Ref failed.");
        return nullptr;
    }
    ani_object outObj = static_cast<ani_object>(callbackRef);
    return outObj;
}

ani_ref AniAppAccountTransfer::GenerateCallbackDynamic(ani_env *aniEnv, uint64_t ptr)
{
    IRemoteObject* rawPtr = reinterpret_cast<IRemoteObject*>(ptr);
    sptr<IRemoteObject> nativeCallback = sptr<IRemoteObject>(rawPtr);
    napi_env jsEnv;
    if (!arkts_napi_scope_open(aniEnv, &jsEnv)) {
        ACCOUNT_LOGE("failed to arkts_napi_scope_open");
        return nullptr;
    }

    napi_value cons = nullptr;
    cons = OHOS::AccountJsKit::NapiAppAccountAuthenticatorCallback::GetConstructor(jsEnv, cons);
    napi_value jsCallback = nullptr;
    napi_new_instance(jsEnv, cons, 0, nullptr, &jsCallback);
    auto callback = new (std::nothrow) OHOS::AccountJsKit::NapiAppAccountAuthenticatorCallback(nativeCallback);
    if (callback == nullptr) {
        ACCOUNT_LOGE("failed to create NapiAppAccountAuthenticatorCallback");
        return nullptr;
    }
    napi_status status = napi_wrap(
        jsEnv, jsCallback, callback,
        [](napi_env jsEnv, void *data, void *hint) {
            ACCOUNT_LOGI("js AuthCallback instance garbage collection");
            delete (reinterpret_cast<AccountJsKit::NapiAppAccountAuthenticatorCallback *>(data));
        },
        nullptr, nullptr);
    if (status != napi_ok) {
        ACCOUNT_LOGE("Wrap js AuthenticatorStub and native callback failed");
        delete callback;
        return nullptr;
    }
    ani_ref outObj;
    if (!arkts_napi_scope_close_n(jsEnv, 1, &jsCallback, &outObj)) {
        ACCOUNT_LOGE("Failed to arkts_napi_scope_close_n");
        return nullptr;
    }
    return outObj;
}

ani_ref AniAppAccountTransfer::NativeAuthCallbackTransferDynamic(ani_env *aniEnv, ani_class aniCls, ani_object input)
{
    ACCOUNT_LOGD("Transfer NativeAuthCallbackTransferDynamic");
    if (aniEnv == nullptr) {
        ACCOUNT_LOGE("null aniEnv");
        return nullptr;
    }
    // 1.2->1.1
    ani_namespace ns;
    if (ANI_OK != aniEnv->FindNamespace(APP_ACCOUNT_TAIHE_NAME_SPACE, &ns)) {
        ACCOUNT_LOGE("Call findNamespace failed.");
        return nullptr;
    }
    ani_function getFunc;
    if (ANI_OK != aniEnv->Namespace_FindFunction(ns, "getAuthCallbackPtr", nullptr, &getFunc)) {
        ACCOUNT_LOGE("Call namespace_FindFunction failed.");
        return nullptr;
    }
    ani_long aniPtr;
    if (ANI_OK != aniEnv->Function_Call_Long(getFunc, &aniPtr, input)) {
        ACCOUNT_LOGE("Call Function_Call_Long failed.");
        return nullptr;
    }
    uint64_t ptr = static_cast<uint64_t>(aniPtr);
    return GenerateCallbackDynamic(aniEnv, ptr);
}

void AniAppAccountTransferInit(ani_env *aniEnv)
{
    ACCOUNT_LOGD("Init app transfer native method");
    if (aniEnv == nullptr) {
        ACCOUNT_LOGE("null ani env");
        return;
    }

    ani_class cls = nullptr;
    auto status = aniEnv->FindClass(ETS_APP_ACCOUNT_TRANSFER_CLASS_NAME, &cls);
    if (status != ANI_OK) {
        ACCOUNT_LOGE("FindClass failed status: %{public}d", status);
        return;
    }

    std::array nativeStaticFuncs = {
        ani_native_function { "nativeAppAccountManagerTransferStatic", nullptr,
            reinterpret_cast<void*>(AniAppAccountTransfer::NativeAppAccountManagerTransferStatic)},
        ani_native_function { "nativeAppAccountManagerTransferDynamic", nullptr,
            reinterpret_cast<void*>(AniAppAccountTransfer::NativeAppAccountManagerTransferDynamic)},

        ani_native_function { "nativeAuthCallbackTransferStatic", nullptr,
            reinterpret_cast<void*>(AniAppAccountTransfer::NativeAuthCallbackTransferStatic)},
        ani_native_function { "nativeAuthCallbackTransferDynamic", nullptr,
            reinterpret_cast<void*>(AniAppAccountTransfer::NativeAuthCallbackTransferDynamic)},
    };
    status = aniEnv->Class_BindStaticNativeMethods(cls, nativeStaticFuncs.data(), nativeStaticFuncs.size());
    if (status != ANI_OK) {
        ACCOUNT_LOGE("Class_BindStaticNativeMethods failed status: %{public}d", status);
        return;
    }

    ACCOUNT_LOGD("Init app transfer native method end");
}
}
}