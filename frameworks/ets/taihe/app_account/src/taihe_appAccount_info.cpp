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

#include "taihe_appAccount_info.h"

namespace OHOS {
namespace AccountSA {
THauthenticatorAsyncCallback::THauthenticatorAsyncCallback()
{}

THauthenticatorAsyncCallback::~THauthenticatorAsyncCallback()
{}
void THauthenticatorAsyncCallback::OnResult(int32_t resultCode, const AAFwk::Want &result)
{
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (isDone) {
            return;
        }
        isDone = true;
    }
    cv.notify_one();

    param = std::make_shared<AuthenticatorCallbackParam>();
    param->resultCode = resultCode;
    param->result = result;
}
void THauthenticatorAsyncCallback::OnRequestRedirected(AAFwk::Want &request)
{};
void THauthenticatorAsyncCallback::OnRequestContinued()
{};
}
}