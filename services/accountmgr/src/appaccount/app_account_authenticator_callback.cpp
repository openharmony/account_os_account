/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

ErrCode AppAccountAuthenticatorCallback::OnResult(int32_t resultCode, const AAFwk::Want &result)
{
    AppAccountAuthenticatorSessionManager::GetInstance().OnSessionResult(sessionId_, resultCode, result);
    return ERR_OK;
}

ErrCode AppAccountAuthenticatorCallback::OnRequestRedirected(const AAFwk::Want &request)
{
    auto newRequest = request;
    AppAccountAuthenticatorSessionManager::GetInstance().OnSessionRequestRedirected(sessionId_, newRequest);
    return ERR_OK;
}

ErrCode AppAccountAuthenticatorCallback::OnRequestContinued()
{
    AppAccountAuthenticatorSessionManager::GetInstance().OnSessionRequestContinued(sessionId_);
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS
