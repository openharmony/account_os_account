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

#include "app_account_authenticator_manager.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
AppAccountAuthenticatorManager::AppAccountAuthenticatorManager()
{}

AppAccountAuthenticatorManager::~AppAccountAuthenticatorManager()
{}

ErrCode AppAccountAuthenticatorManager::GetAuthenticatorInfo(
    const std::string &owner, int32_t userId, AuthenticatorInfo &info)
{
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS
