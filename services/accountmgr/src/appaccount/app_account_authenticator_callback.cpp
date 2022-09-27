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

#include "app_account_authenticator_callback.h"

#include "account_log_wrapper.h"
#include "app_account_authenticator_session.h"

namespace OHOS {
namespace AccountSA {
AppAccountAuthenticatorCallback::AppAccountAuthenticatorCallback(const std::string &sessionId)
    : sessionId_(sessionId)
{}

AppAccountAuthenticatorCallback::~AppAccountAuthenticatorCallback()
{}

void AppAccountAuthenticatorCallback::OnResult(int32_t resultCode, const AAFwk::Want &result)
{
    auto sessionMgr = AppAccountAuthenticatorSessionManager::GetInstance();
    if (sessionMgr != nullptr) {
        sessionMgr->OnSessionResult(sessionId_, resultCode, result);
    }
}

void AppAccountAuthenticatorCallback::OnRequestRedirected(AAFwk::Want &request)
{
    auto sessionMgr = AppAccountAuthenticatorSessionManager::GetInstance();
    if (sessionMgr != nullptr) {
        sessionMgr->OnSessionRequestRedirected(sessionId_, request);
    }
}

void AppAccountAuthenticatorCallback::OnRequestContinued()
{
    auto sessionMgr = AppAccountAuthenticatorSessionManager::GetInstance();
    if (sessionMgr != nullptr) {
        sessionMgr->OnSessionRequestContinued(sessionId_);
    }
}
}  // namespace AccountSA
}  // namespace OHOS
