/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "accesstoken_kit.h"

#include "account_log_wrapper.h"

using namespace OHOS::AccountSA;

namespace OHOS {
namespace Security {
namespace AccessToken {
int AccessTokenKit::VerifyAccessToken(unsigned int tokenID, const std::string &permissionName)
{
    ACCOUNT_LOGI("mock permissionName = %{public}s", permissionName.c_str());

    return PERMISSION_GRANTED;
}
int AccessTokenKit::GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfo& hapTokenInfoRes)
{
    ACCOUNT_LOGI("mock GetHapTokenInfo enter");
    hapTokenInfoRes.instIndex = 0;
    return 0;
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
