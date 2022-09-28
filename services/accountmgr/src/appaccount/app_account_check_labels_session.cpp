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

#include "app_account_check_labels_session.h"

#include "app_account_common.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
AppAccountCheckLabelsSession::AppAccountCheckLabelsSession(
    std::vector<AppAccountInfo> accounts, const AuthenticatorSessionRequest &request)
    : AppAccountAuthenticatorSession(CHECK_ACCOUNT_LABELS, request), accounts_(accounts)
{}

AppAccountCheckLabelsSession::~AppAccountCheckLabelsSession()
{}

ErrCode AppAccountCheckLabelsSession::Open()
{
    if (isOpened_) {
        return ERR_APPACCOUNT_SERVICE_OAUTH_SERVICE_EXCEPTION;
    }
    checkCallback_ = new (std::nothrow) AppAccountCheckLabelsCallback(accounts_, request_, sessionId_);
    if (checkCallback_ == nullptr) {
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    isOpened_ = true;
    return ERR_OK;
}

ErrCode AppAccountCheckLabelsSession::CheckLabels()
{
    return checkCallback_->CheckLabels();
}

void AppAccountCheckLabelsSession::GetRequest(AuthenticatorSessionRequest &request) const
{
    request = request_;
}
}  // namespace AccountSA
}  // namespace OHOS