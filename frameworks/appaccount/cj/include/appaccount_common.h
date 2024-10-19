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


#ifndef APPACCOUNT_COMMON_H
#define APPACCOUNT_COMMON_H

#include <mutex>
#include <thread>
#include "app_account_authenticator_callback_stub.h"
#include "app_account_common.h"
#include "app_account_manager.h"
#include "app_account_subscriber.h"
#include "cj_common_ffi.h"
#include "want.h"
#include "appaccount_defination.h"

namespace OHOS::AccountSA {
class SubscribePtr : public AppAccountSubscriber {
public:
    explicit SubscribePtr(const AppAccountSubscribeInfo &subscribeInfo);
    void SetCallbackRef(std::function<void(CArrAppAccountInfo)> callbackRef);
    void OnAccountsChanged(const std::vector<AppAccountInfo>  &accounts) override;
    std::function<void(CArrAppAccountInfo)> ref_;
};

struct AsyncContextForSubscribe {
    std::string type;
    std::vector<std::string> owners;
    std::shared_ptr<SubscribePtr> subscriber = nullptr;
    std::function<void(CArrAppAccountInfo)> callbackRef;
};

struct AsyncContextForUnSubscribe {
    std::string type;
    std::vector<std::shared_ptr<SubscribePtr>> subscribers = {nullptr};
    std::function<void(CArrAppAccountInfo)> callbackRef;
};

struct CheckAccountLabelsContext {
    std::string name;
    std::string owner;
    std::vector<std::string> labels;
    std::function<void(RetDataBool)> callbackRef = nullptr;
    sptr<IAppAccountAuthenticatorCallback> appAccountMgrCb = nullptr;
    ErrCode errCode = ERR_OK;
};

class AuthenticatorAsyncCallback : public AppAccountAuthenticatorCallbackStub {
public:
    explicit AuthenticatorAsyncCallback(
        std::function<void(RetDataBool)> cRef, std::function<void(ErrCArrAppAccountInfo)> sRef);
    ~AuthenticatorAsyncCallback();

    void OnResult(int32_t resultCode, const AAFwk::Want &result) override;
    void OnRequestRedirected(AAFwk::Want &request) override;
    void OnRequestContinued() override;

    bool onResultRetBool = false;
    std::vector<std::string> onResultRetNames;
    std::vector<std::string> onResultRetOwners;
    AAFwk::Want result_;
    AAFwk::Want request_;
    ErrCode errCode = ERR_OK;

private:
    std::mutex mutex_;
    bool isDone = false;
    std::function<void(RetDataBool)> checkAccountLabelsCallbackRef = nullptr;
    std::function<void(ErrCArrAppAccountInfo)> selectAccountsCallbackRef = nullptr;
};

struct SelectAccountsContext {
    SelectAccountsOptions options;
    std::vector<AppAccountInfo> appAccountInfos;
    std::function<void(ErrCArrAppAccountInfo)> callbackRef = nullptr;
    sptr<IAppAccountAuthenticatorCallback> appAccountMgrCb = nullptr;
    ErrCode errCode = ERR_OK;
};

struct JSAuthCallback {
    std::function<void(int32_t, CAuthResult)> onResult = nullptr;
    std::function<void(WantHandle)> onRequestRedirected = nullptr;
    std::function<void()> onRequestContinued = nullptr;
};

class AppAccountManagerCallback : public AppAccountAuthenticatorCallbackStub {
public:
    explicit AppAccountManagerCallback(JSAuthCallback callback);
    ~AppAccountManagerCallback();

    void OnResult(int32_t resultCode, const AAFwk::Want &result) override;
    void OnRequestRedirected(AAFwk::Want &request) override;
    void OnRequestContinued() override;

    AAFwk::Want result_;
    JSAuthCallback callback_;
    ErrCode errCode = ERR_OK;
    // account: AppAccountInfo
    std::string nameResult;
    std::string ownerResult;
    //tokenInfo: AuthTokenInfo
    std::string authTypeResult;
    std::string tokenResult;

private:
    std::mutex mutex_;
    bool isDone = false;
};
} // namespace OHOS::AccountSA
#endif