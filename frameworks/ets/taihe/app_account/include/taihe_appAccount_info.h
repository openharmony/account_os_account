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

namespace OHOS {
namespace AccountSA {

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
    std::shared_ptr<AuthenticatorCallbackParam> param_;
    std::mutex mutex_;
    bool isDone_ = false;
    std::condition_variable cv_;
};
    
} // namespace AccountSA
} // namespace OHOS

#endif // OHOS_ACCOUNT_DISTRIBUTED_ACCOUNT_H