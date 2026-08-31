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

#ifndef TAIHE_AUTHORIZATION_CALLBACK_BASE_H
#define TAIHE_AUTHORIZATION_CALLBACK_BASE_H

#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include "account_constants.h"
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "ani_ui_extension.h"
#include "authorization_callback.h"

namespace OHOS {
namespace AccountSA {

ErrCode NotifyAuthorizationResultWithRetry(const sptr<IRemoteObject>& callback, int32_t errCode,
    const std::vector<uint8_t> &iamToken = {}, int32_t accountId = -1, int32_t resultCode = 0);

template <typename ResultType>
class TaiheAuthorizationCallback : public AuthorizationCallback {
public:
    using BuildResultFunc = std::function<ResultType(const AuthorizationResult&, const std::string&)>;

    TaiheAuthorizationCallback(
        std::shared_ptr<TaiheAcquireAuthorizationContext> &context,
        std::string privilege, BuildResultFunc buildResultFunc)
        : buildResultFunc_(std::move(buildResultFunc))
    {
        context_ = context;
        privilege_ = std::move(privilege);
    }

    ~TaiheAuthorizationCallback() override = default;

    ErrCode OnResult(int32_t errCode, const AuthorizationResult &result) override
    {
        std::unique_lock<std::mutex> lock(mutex_);
        if (onResultCalled_) {
            ACCOUNT_LOGE("OnResult has been called.");
            return ERR_OK;
        }
        if (context_ != nullptr && context_->hasOptions && context_->options.hasContext) {
            CloseUIExtension(context_);
        }
        errCode_ = errCode;
        if (buildResultFunc_ != nullptr) {
            taiheResult_ = buildResultFunc_(result, privilege_);
        }
        onResultCalled_ = true;
        cv_.notify_one();
        return ERR_OK;
    }

    ErrCode OnConnectAbility(const ConnectAbilityInfo &info,
        const sptr<IRemoteObject> &callback) override
    {
        ACCOUNT_LOGI("TaiheAuthorizationCallback OnConnectAbility");
        if (context_ == nullptr) {
            std::unique_lock<std::mutex> lock(mutex_);
            errCode_ = ERR_JS_SYSTEM_SERVICE_EXCEPTION;
            cv_.notify_one();
            return ERR_AUTHORIZATION_CREATE_UI_EXTENSION_ERROR;
        }
        if (!context_->hasOptions || !context_->options.hasContext) {
            std::unique_lock<std::mutex> lock(mutex_);
            errCode_ = ERR_JS_SYSTEM_SERVICE_EXCEPTION;
            cv_.notify_one();
            return ERR_AUTHORIZATION_CREATE_UI_EXTENSION_ERROR;
        }
        ErrCode errCode = CreateUIExtension(context_, info, callback);
        if (errCode == ERR_OK) {
            return ERR_OK;
        }
        auto connectCallback = iface_cast<IConnectAbilityCallback>(callback);
        if (connectCallback == nullptr) {
            std::unique_lock<std::mutex> lock(mutex_);
            errCode_ = ERR_JS_SYSTEM_SERVICE_EXCEPTION;
            cv_.notify_one();
            return ERR_OK;
        }
        std::vector<uint8_t> iamToken;
        NotifyAuthorizationResultWithRetry(callback, errCode, iamToken, -1, 0);
        return ERR_OK;
    }

    int32_t errCode_ = -1;
    std::mutex mutex_;
    std::condition_variable cv_;
    bool onResultCalled_ = false;
    std::shared_ptr<TaiheAcquireAuthorizationContext> context_;
    std::string privilege_;
    std::optional<ResultType> taiheResult_;

private:
    BuildResultFunc buildResultFunc_;
};

template <typename ResultType>
static inline ResultType TaiheWaitForAuthorizationResult(
    const std::shared_ptr<TaiheAuthorizationCallback<ResultType>> &callback)
{
    std::unique_lock<std::mutex> lock(callback->mutex_);
    callback->cv_.wait(lock, [callback] { return callback->onResultCalled_; });
    return std::move(*callback->taiheResult_);
}

} // namespace AccountSA
} // namespace OHOS

#endif // TAIHE_AUTHORIZATION_CALLBACK_BASE_H
