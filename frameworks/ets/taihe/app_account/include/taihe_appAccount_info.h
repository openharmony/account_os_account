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
#include "app_account_common.h"
#include "app_account_manager.h"
#include "napi_app_account_transfer.h"

using SubscribeCallback = taihe::callback<void(taihe::array_view<ohos::account::appAccount::AppAccountInfo>)>;

namespace OHOS {
namespace AccountSA {

class SubscriberPtr : public AccountSA::AppAccountSubscriber {
public:
    SubscriberPtr(const AccountSA::AppAccountSubscribeInfo &subscribeInfo,
        SubscribeCallback callback);
    ~SubscriberPtr() override;
    void OnAccountsChanged(const std::vector<AccountSA::AppAccountInfo> &accounts) override;

public:
    std::mutex mutex_;
    SubscribeCallback callback_;
};

struct AsyncContextForSubscribe : public AccountJsKit::AsyncContextForSubscribeBase {
    explicit AsyncContextForSubscribe(SubscribeCallback callback): callbackRef(callback) {};
    uint64_t appAccountManagerHandle = 0;
    std::shared_ptr<SubscriberPtr> subscriber = nullptr;
    SubscribeCallback callbackRef;
};

struct AsyncContextForUnsubscribe {
    std::string type;
    std::vector<std::shared_ptr<AccountSA::SubscriberPtr>> subscribers;
    uint64_t appAccountManagerHandle = 0;
    size_t argc = 0;
};

struct AuthenticatorCallbackParam {
    int32_t resultCode = -1;
    AAFwk::Want result;
};

class THauthenticatorAsyncCallback : public AccountSA::AppAccountAuthenticatorCallbackStub {
public:
    explicit THauthenticatorAsyncCallback();
    ~THauthenticatorAsyncCallback() override;
    ErrCode OnResult(int32_t resultCode, const AAFwk::Want &result) override;
    ErrCode OnRequestRedirected(const AAFwk::Want &request) override;
    ErrCode OnRequestContinued() override;

public:
    std::shared_ptr<AuthenticatorCallbackParam> param_;
    std::mutex mutex_;
    bool isDone_ = false;
    std::condition_variable cv_;
};
    
} // namespace AccountSA
} // namespace OHOS

#endif // OHOS_ACCOUNT_DISTRIBUTED_ACCOUNT_H