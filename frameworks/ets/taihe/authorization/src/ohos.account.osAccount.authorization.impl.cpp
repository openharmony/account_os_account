/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "account_log_wrapper.h"
#include "account_error_no.h"
#include "authorization_client.h"
#include "authorization_callback.h"
#include "authorization_privilege.h"
#include "napi_account_error.h"
#include "ohos.account.osAccount.authorization.impl.hpp"
#include "ohos.account.osAccount.authorization.proj.hpp"
#include "taihe/runtime.hpp"
#include "taihe_authorization_callback_base.h"

using namespace taihe;
using namespace OHOS;
using namespace ohos::account::osAccount::authorization;

namespace {
using OHOS::AccountSA::ACCOUNT_LABEL;

AuthorizationResultCode::key_t ConvertToAuthorizationResultCodeKey(AccountSA::AuthorizationResultCode type)
{
    switch (type) {
        case AccountSA::AuthorizationResultCode::AUTHORIZATION_SUCCESS:
            return AuthorizationResultCode::key_t::AUTHORIZATION_GRANTED;
        case AccountSA::AuthorizationResultCode::AUTHORIZATION_CANCELED:
            return AuthorizationResultCode::key_t::AUTHORIZATION_CANCELED;
        case AccountSA::AuthorizationResultCode::AUTHORIZATION_DENIED:
            return AuthorizationResultCode::key_t::AUTHORIZATION_DENIED;
        case AccountSA::AuthorizationResultCode::AUTHORIZATION_PRIVILEGE_NOT_SUPPORTED:
            return AuthorizationResultCode::key_t::AUTHORIZATION_NOT_SUPPORTED;
        default:
            return AuthorizationResultCode::key_t::AUTHORIZATION_DENIED;
    }
}
void SetAuthorizationBusinessError(int32_t nativeErrCode)
{
    if (nativeErrCode == ERR_OK) {
        return;
    }
    int32_t jsErrCode = OHOS::AuthorizationConvertToJsErrCode(nativeErrCode);
    std::string errMsg = OHOS::ConvertToJsErrMsg(jsErrCode);
    taihe::set_business_error(jsErrCode, errMsg.c_str());
}

static ohos::account::osAccount::authorization::AuthorizationResult InitializeAuthorizationResult()
{
    return ohos::account::osAccount::authorization::AuthorizationResult{
        .resultCode = AuthorizationResultCode(AuthorizationResultCode::key_t::AUTHORIZATION_GRANTED),
        .privilege = Privilege::from_value("")
    };
}

using TaiheAuthPublicCallback = OHOS::AccountSA::TaiheAuthorizationCallback<
    ohos::account::osAccount::authorization::AuthorizationResult>;

static ohos::account::osAccount::authorization::AuthorizationResult BuildPublicAuthorizationResult(
    const OHOS::AccountSA::AuthorizationResult &result, const std::string &privilege)
{
    return ohos::account::osAccount::authorization::AuthorizationResult{
        .resultCode = AuthorizationResultCode(ConvertToAuthorizationResultCodeKey(result.resultCode)),
        .privilege = Privilege::from_value(privilege)
    };
}

static ohos::account::osAccount::authorization::AuthorizationResult WaitForAuthorizationResult(
    const std::shared_ptr<TaiheAuthPublicCallback>& callback)
{
    std::unique_lock<std::mutex> lock(callback->mutex_);
    callback->cv_.wait(lock, [callback] { return callback->onResultCalled_; });

    if (callback->errCode_ != ERR_OK) {
        ACCOUNT_LOGE("AcquireAuthorization failed with errCode: %{public}d", callback->errCode_);
        auto rc = callback->errCode_;
        if (rc == static_cast<int32_t>(
                AccountSA::AuthorizationResultCode::AUTHORIZATION_INTERACTION_NOT_ALLOWED)) {
            std::string errMsg = ConvertToJsErrMsg(ERR_JS_AUTHORIZATION_INTERACTION_NOT_ALLOWED);
            taihe::set_business_error(ERR_JS_AUTHORIZATION_INTERACTION_NOT_ALLOWED, errMsg.c_str());
        } else if (rc == static_cast<int32_t>(
                       AccountSA::AuthorizationResultCode::AUTHORIZATION_SERVICE_BUSY)) {
            std::string errMsg = ConvertToJsErrMsg(ERR_JS_AUTHORIZATION_SERVICE_BUSY);
            taihe::set_business_error(ERR_JS_AUTHORIZATION_SERVICE_BUSY, errMsg.c_str());
        } else {
            SetAuthorizationBusinessError(callback->errCode_);
        }
        return InitializeAuthorizationResult();
    }
    return std::move(*callback->taiheResult_);
}

class AuthorizationManagerImpl {
public:
    AuthorizationManagerImpl() {}

    ohos::account::osAccount::authorization::AuthorizationResult AcquireAuthorizationPromise(
        Privilege privilege, uintptr_t context)
    {
        ani_env *env = get_env();
        std::string privilegeStr = privilege.get_value();
        ohos::account::osAccount::authorization::AuthorizationResult taiheResult = InitializeAuthorizationResult();

        auto authContext = std::make_shared<OHOS::AccountSA::TaiheAcquireAuthorizationContext>(env);
        authContext->hasOptions = true;
        authContext->options.hasContext = true;
        authContext->isPublicApi = true;

        bool isContextValid = false;
        ani_object aniContext = reinterpret_cast<ani_object>(context);
        if (authContext->FillInfoFromContext(aniContext)) {
            if (authContext->IsUIAbilityContext()) {
                isContextValid = true;
            } else {
                ACCOUNT_LOGE("Context is not UIAbilityContext, not supported in public API");
                std::string errMsg = ConvertToJsErrMsg(ERR_JS_PARAMETER_ERROR);
                taihe::set_business_error(ERR_JS_PARAMETER_ERROR, errMsg.c_str());
                return taiheResult;
            }
        }

        auto callback = std::make_shared<TaiheAuthPublicCallback>(authContext, privilegeStr,
            BuildPublicAuthorizationResult);
        ErrCode errCode = OHOS::AccountSA::AuthorizationClient::GetInstance().AcquireAuthorizationForPublic(
            privilegeStr, isContextValid, callback);
        if (errCode != ERR_OK) {
            SetAuthorizationBusinessError(errCode);
            return taiheResult;
        }
        return WaitForAuthorizationResult(callback);
    }

    bool HasAuthorizationPromise(Privilege privilege)
    {
        std::string privilegeStr = privilege.get_value();
        bool isAuthorized = false;
        ErrCode errCode = OHOS::AccountSA::AuthorizationClient::GetInstance().HasAuthorizationForPublic(
            privilegeStr, isAuthorized);
        if (errCode != ERR_OK) {
            SetAuthorizationBusinessError(errCode);
            return false;
        }
        return isAuthorized;
    }
};

AuthorizationManager GetAuthorizationManager()
{
    return make_holder<AuthorizationManagerImpl, AuthorizationManager>();
}

} // namespace

TH_EXPORT_CPP_API_GetAuthorizationManager(GetAuthorizationManager);
