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
 
#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_CHECK_LABELS_SESSION_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_CHECK_LABELS_SESSION_H

#include "app_account_authenticator_session.h"
#include "app_account_check_labels_callback.h"

namespace OHOS {
namespace AccountSA {
class AppAccountCheckLabelsSession : public AppAccountAuthenticatorSession {
public:
    explicit AppAccountCheckLabelsSession(
        std::vector<AppAccountInfo> accounts, const AuthenticatorSessionRequest &request);
    ~AppAccountCheckLabelsSession() override;

    ErrCode Open() override;
    ErrCode CheckLabels();
    void GetRequest(AuthenticatorSessionRequest &request) const override;

private:
    std::vector<AppAccountInfo> accounts_;
    sptr<AppAccountCheckLabelsCallback> checkCallback_;
};
}
}
#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_CHECK_LABELS_SESSION_H
