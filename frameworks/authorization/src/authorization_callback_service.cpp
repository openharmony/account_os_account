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

#include "authorization_callback_service.h"
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "authorization_callback.h"
#include "authorization_callback_stub.h"

namespace OHOS {
namespace AccountSA {
/**
 * @brief Constructor for AuthorizationCallbackService.
 * @param callback The inner authorization callback
 * @param afterOnResult The cleanup function to call after OnResult completes
 */
AuthorizationCallbackService::AuthorizationCallbackService(const std::shared_ptr<AuthorizationCallback> &callback,
    std::function<void()> afterOnResult)
{
    innerCallback_ = callback;
    afterOnResult_ = afterOnResult;
}

AuthorizationCallbackService::~AuthorizationCallbackService()
{}

/**
 * @brief Handle authorization result callback.
 * @param resultCode The result code from authorization service
 * @param result The authorization result containing token and other information
 * @return ERR_OK on success
 */
ErrCode AuthorizationCallbackService::OnResult(int32_t resultCode, const AccountSA::AuthorizationResult& result)
{
    ACCOUNT_LOGI("OnResult resultCode:%{public}d", resultCode);
    sptr<AuthorizationCallbackService> self = this;
    if (innerCallback_ == nullptr) {
        ACCOUNT_LOGE("Inner callback is nullptr");
        // Still call afterOnResult_ for cleanup even if callback is null
        if (afterOnResult_ != nullptr) {
            afterOnResult_();
        }
        return ERR_OK;
    }

    ErrCode ret = innerCallback_->OnResult(resultCode, result);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Inner callback OnResult failed, errCode:%{public}d", ret);
    }

    if (afterOnResult_ != nullptr) {
        afterOnResult_();
    }
    return ERR_OK;
}

/**
 * @brief Handle connect ability callback for UI extension.
 * @param info The connection ability information
 * @param callback The callback remote object
 * @return ERR_OK on success
 */
ErrCode AuthorizationCallbackService::OnConnectAbility(const AccountSA::ConnectAbilityInfo &info,
    const sptr<IRemoteObject> &callback)
{
    ACCOUNT_LOGI("OnConnectAbility bundleName:%{public}s", info.bundleName.c_str());
    if (innerCallback_ == nullptr) {
        ACCOUNT_LOGE("Inner callback is nullptr");
        return ERR_OK;
    }

    ErrCode ret = innerCallback_->OnConnectAbility(info, callback);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Inner callback OnConnectAbility failed, errCode:%{public}d", ret);
    }
    return ERR_OK;
}
}
}