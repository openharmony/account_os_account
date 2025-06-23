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

#ifndef OHOS_ACCOUNT_APP_ACCOUNT_H
#define OHOS_ACCOUNT_APP_ACCOUNT_H

#include "ohos.account.appAccount.proj.hpp"
#include "ohos.account.appAccount.impl.hpp"

#include "ani_common_want.h"
#include "app_account_authenticator_callback_stub.h"

#include "app_account_authenticator_stub.h"
#include "app_account_authenticator_callback_stub.h"
#include "app_account_common.h"
#include "app_account_manager.h"

using active_callback = taihe::callback_view<void(taihe::array_view<ohos::account::appAccount::AppAccountInfo>)>;

namespace OHOS {
namespace AccountSA {

struct AsyncContextForSubscribe;
class SubscriberPtr;

const char TYPE_CHANGE[] = "change";

struct AsyncContextForUnsubscribe {
    std::string type;
    std::vector<std::shared_ptr<AccountSA::SubscriberPtr>> subscribers = {nullptr};
    AccountSA::AppAccountManager *appAccountManager = nullptr;
    size_t argc = 0;
};

struct AsyncContextForSubscribe
{
    std::string type;
    std::vector<std::string> owners;
    AccountSA::AppAccountManager *appAccountManager = nullptr;
    std::shared_ptr<SubscriberPtr> subscriber = nullptr;
};

class SubscriberPtr : public AccountSA::AppAccountSubscriber {
public:
    explicit SubscriberPtr(const AccountSA::AppAccountSubscribeInfo &subscribeInfo,
        active_callback callback);
    ~SubscriberPtr() override;
    void OnAccountsChanged(const std::vector<AccountSA::AppAccountInfo> &accounts) override;

public:
    std::mutex mutex_;
    bool isDone = false;
    active_callback callback_;
};

class AppAccountManagerCallback : public OHOS::AccountSA::AppAccountAuthenticatorCallbackStub {
public:
    explicit AppAccountManagerCallback(ohos::account::appAccount::AuthCallback callback);
    ~AppAccountManagerCallback() override;
    void OnResult(int32_t resultCode, const AAFwk::Want &result) override;
    void OnRequestRedirected(AAFwk::Want &request) override;
    void OnRequestContinued() override;

    std::mutex mutex_;
    bool isDone = false;
    ohos::account::appAccount::AuthCallback callback_;
    std::condition_variable cv;
};

struct AuthenticatorCallbackParam {
    int32_t resultCode = -1;
    AAFwk::Want result;
};

struct AuthenticatorCallbackParam {
    int32_t resultCode = -1;
    AAFwk::Want result;
};

class THauthenticatorAsyncCallback : public AccountSA::AppAccountAuthenticatorCallbackStub {
public:
    explicit THauthenticatorAsyncCallback();
    ~THauthenticatorAsyncCallback() override;
    void OnResult(int32_t resultCode, const AAFwk::Want &result) override;
    void OnRequestRedirected(AAFwk::Want &request) override;
    void OnRequestContinued() override;

public:
    std::shared_ptr<AuthenticatorCallbackParam> param;
    std::mutex mutex;
    bool isDone = false;
    std::condition_variable cv;
};
    
} // namespace AccountSA
} // namespace OHOS

#endif // OHOS_ACCOUNT_DISTRIBUTED_ACCOUNT_H