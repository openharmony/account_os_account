/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
 
#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_CHECK_LABELS_CALLBACK_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_CHECK_LABELS_CALLBACK_H

#include "app_account_authenticator_callback_stub.h"
#include "app_account_common.h"
#include "app_account_info.h"
#include "want.h"

namespace OHOS {
namespace AccountSA {
class AppAccountCheckLabelsCallback : public AppAccountAuthenticatorCallbackStub {
public:
    explicit AppAccountCheckLabelsCallback(std::vector<AppAccountInfo> accounts,
        const AuthenticatorSessionRequest &request, const std::string &sessionId);
    ~AppAccountCheckLabelsCallback() override;

    void OnResult(int32_t resultCode, const AAFwk::Want &result) override;
    void OnRequestRedirected(AAFwk::Want &request) override;
    void OnRequestContinued() override;
    ErrCode CheckLabels();

private:
    void SendResult(int32_t resultCode);

private:
    std::vector<AppAccountInfo> accounts_;
    AuthenticatorSessionRequest request_;
    std::vector<std::string> labels_;
    std::vector<AppAccountInfo> accountsWithLabels_;
    std::uint32_t index_ = 0;
    std::string sessionId_;
};
}
}
#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_CHECK_LABELS_CALLBACK_H
