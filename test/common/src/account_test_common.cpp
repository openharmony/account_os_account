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

#include "account_test_common.h"
#include <sstream>
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "token_setproc.h"

namespace OHOS {
namespace AccountSA {
using namespace OHOS::AccountSA;
using namespace OHOS::Security::AccessToken;

namespace {
    static uint64_t g_shellTokenID = IPCSkeleton::GetSelfTokenID();
}

static uint64_t GetTokenId(const AtmToolsParamInfo &info)
{
    std::string dumpInfo;
    AccessTokenKit::DumpTokenInfo(info, dumpInfo);
    size_t pos = dumpInfo.find("\"tokenID\": ");
    if (pos == std::string::npos) {
        return 0;
    }
    pos += std::string("\"tokenID\": ").length();
    std::string numStr;
    while (pos < dumpInfo.length() && std::isdigit(dumpInfo[pos])) {
        numStr += dumpInfo[pos];
        ++pos;
    }

    std::istringstream iss(numStr);
    uint64_t tokenID;
    iss >> tokenID;
    return tokenID;
}

uint64_t GetTokenIdFromProcess(const std::string &process)
{
    auto tokenId = IPCSkeleton::GetSelfTokenID();
    SetSelfTokenID(g_shellTokenID); // only shell can dump tokenid

    AtmToolsParamInfo info;
    info.processName = process;
    auto res = GetTokenId(info);

    SetSelfTokenID(tokenId);
    return res;
}

uint64_t GetTokenIdFromBundleName(const std::string &bundleName)
{
    auto tokenId = IPCSkeleton::GetSelfTokenID();
    SetSelfTokenID(g_shellTokenID); // only shell can dump tokenid

    AtmToolsParamInfo info;
    info.bundleName = bundleName;
    auto res = GetTokenId(info);

    SetSelfTokenID(tokenId);
    return res;
}

bool MockTokenId(const std::string &process)
{
    auto mockTokenId = GetTokenIdFromProcess(process);
    if (mockTokenId == 0) {
        return false;
    }
    if (SetSelfTokenID(mockTokenId) != 0) {
        return false;
    }
    return IPCSkeleton::GetSelfTokenID() != 0;
}

bool AllocPermission(std::vector<std::string> permissions, uint64_t &tokenID, bool isSystemApp)
{
    if (!MockTokenId("foundation")) {
        return false;
    }
    std::vector<PermissionStateFull> permissionStates;
    for (const auto& permission : permissions) {
        PermissionStateFull permissionState = {
            .permissionName = permission,
            .isGeneral = true,
            .resDeviceID = {"local"},
            .grantStatus = {PermissionState::PERMISSION_GRANTED},
            .grantFlags = {PERMISSION_SYSTEM_FIXED}
        };
        permissionStates.emplace_back(permissionState);
    }
    HapPolicyParams hapPolicyParams = {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permList = {},
        .permStateList = permissionStates
    };

    HapInfoParams hapInfoParams = {
        .userID = 100,
        .bundleName = "account_test",
        .instIndex = 0,
        .appIDDesc = "account_test",
        .apiVersion = 8,
        .isSystemApp = isSystemApp
    };

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(hapInfoParams, hapPolicyParams);
    tokenID = tokenIdEx.tokenIDEx;
    if (!((INVALID_TOKENID != tokenIdEx.tokenIDEx) && (0 == SetSelfTokenID(tokenIdEx.tokenIDEx)))) {
        return false;
    }
    return tokenID == IPCSkeleton::GetSelfTokenID();
}

bool RecoveryPermission(uint64_t tokenID, uint64_t oldTokenID)
{
    if (!MockTokenId("foundation")) {
        return false;
    }
    if (!((ERR_OK == AccessTokenKit::DeleteToken(tokenID)) && (ERR_OK == SetSelfTokenID(oldTokenID)))) {
        return false;
    }
    return oldTokenID == IPCSkeleton::GetSelfTokenID();
}

uint64_t GetAllAccountPermission()
{
    if (!MockTokenId("foundation")) {
        return 0;
    }
    std::vector<PermissionStateFull> permissionStates;
    for (const auto& permission : ALL_ACCOUNT_PERMISSION_LIST) {
        PermissionStateFull permissionState = {
            .permissionName = permission,
            .isGeneral = true,
            .resDeviceID = {"local"},
            .grantStatus = {PermissionState::PERMISSION_GRANTED},
            .grantFlags = {PERMISSION_SYSTEM_FIXED}
        };
        permissionStates.emplace_back(permissionState);
    }
    HapPolicyParams hapPolicyParams = {
        .apl = APL_NORMAL,
        .domain = "account_test_setup.domain",
        .permList = {},
        .permStateList = permissionStates
    };

    HapInfoParams hapInfoParams = {
        .userID = 100,
        .bundleName = "account_test_setup",
        .instIndex = 0,
        .appIDDesc = "account_test_setup",
        .apiVersion = 8,
        .isSystemApp = true
    };

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(hapInfoParams, hapPolicyParams);
    auto tokenID = tokenIdEx.tokenIDEx;
    if (!((INVALID_TOKENID != tokenIdEx.tokenIDEx) && (0 == SetSelfTokenID(tokenIdEx.tokenIDEx)) &&
          (tokenID == IPCSkeleton::GetSelfTokenID()))) {
        return 0;
    }
    return tokenID;
}
} // namespace AccountSA
} // namespace OHOS