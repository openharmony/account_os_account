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

#include "account_permission_manager.h"

#include "accesstoken_kit.h"
#include "account_log_wrapper.h"
#include "account_constants.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"

using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace AccountSA {
ErrCode AccountPermissionManager::VerifyPermission(const std::string &permissionName)
{
    AccessTokenID callingToken = IPCSkeleton::GetCallingTokenID();
    ErrCode result = AccessTokenKit::VerifyAccessToken(callingToken, permissionName);
    if (result == TypePermissionState::PERMISSION_DENIED) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    return ERR_OK;
}

ErrCode AccountPermissionManager::CheckSystemApp(bool isCallStub)
{
    uint64_t fullTokenId;
    if (isCallStub) {
        fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    } else {
        fullTokenId = IPCSkeleton::GetSelfTokenID();
    }
    AccessTokenID tokenId = fullTokenId & TOKEN_ID_LOWMASK;
    ATokenTypeEnum tokenType = AccessTokenKit::GetTokenType(tokenId);
    if ((tokenType == ATokenTypeEnum::TOKEN_HAP) && (!TokenIdKit::IsSystemAppByFullTokenID(fullTokenId))) {
        return ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR;
    }
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS
