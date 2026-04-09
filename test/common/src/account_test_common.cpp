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
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <sstream>
#include <unistd.h>
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "os_account.h"
#include "os_account_manager.h"
#include "token_setproc.h"
#include "account_log_wrapper.h"
#include "os_account_constants.h"

#ifdef SUPPORT_AUTHORIZATION
#ifdef HAS_PIN_AUTH_PART
#include "account_iam_client.h"
#include "authorization_client.h"
#include "authorization_common.h"
#endif
#endif

namespace OHOS {
namespace AccountSA {
using namespace OHOS::AccountSA;
using namespace OHOS::Security::AccessToken;

namespace {
    static uint64_t g_shellTokenID = IPCSkeleton::GetSelfTokenID();
#ifdef SUPPORT_AUTHORIZATION
    constexpr uid_t MAINTENANCE_UID_FOR_TEST = 4444;
    constexpr uid_t ROOT_UID_FOR_TEST = 0;
#ifdef HAS_PIN_AUTH_PART
    constexpr int64_t AUTHORIZATION_WAIT_TIMEOUT_MS = 5000;
    const std::vector<std::string> AUTHORIZATION_PERMISSION_LIST = {
        "ohos.permission.MANAGE_LOCAL_ACCOUNTS",
        "ohos.permission.GET_LOCAL_ACCOUNTS",
        "ohos.permission.MANAGE_DISTRIBUTED_ACCOUNTS",
        "ohos.permission.GET_DISTRIBUTED_ACCOUNTS",
        "ohos.permission.DISTRIBUTED_DATASYNC",
        "ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS",
        "ohos.permission.GET_LOCAL_ACCOUNT_IDENTIFIERS",
        "ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION",
        "ohos.permission.ACCESS_PIN_AUTH",
        "ohos.permission.ACCESS_USER_AUTH_INTERNAL",
        "ohos.permission.ACQUIRE_LOCAL_ACCOUNT_AUTHORIZATION",
        "ohos.permission.START_SYSTEM_DIALOG",
    };

class TestPinInputer final : public IInputer {
public:
    void OnGetData(int32_t authSubType, std::vector<uint8_t> challenge,
        std::shared_ptr<IInputerData> inputerData) override
    {
        if (inputerData != nullptr) {
            inputerData->OnSetData(authSubType, {0, 0, 0, 0, 0, 0});
        }
    }
};

class TestAdminAuthorizationCallback final : public AdminAuthorizationCallback {
public:
    int32_t OnResult(const AdminAuthorizationResult &result) override
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            result_ = result;
            completed_ = true;
        }
        condition_.notify_one();
        return ERR_OK;
    }

    bool WaitForResult(AdminAuthorizationResult &result)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        if (!condition_.wait_for(lock, std::chrono::milliseconds(AUTHORIZATION_WAIT_TIMEOUT_MS),
            [this]() { return completed_; })) {
            return false;
        }
        result = result_;
        return true;
    }

private:
    std::mutex mutex_;
    std::condition_variable condition_;
    bool completed_ = false;
    AdminAuthorizationResult result_;
};
#endif
#endif
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
        .bundleName = "com.ohos.sceneboard",
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

#ifdef SUPPORT_AUTHORIZATION
template<typename Func>
ErrCode ExecuteWithUid(uid_t uid, Func &&func)
{
    if (setuid(uid) != 0) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    ErrCode errCode = func();
    if (setuid(ROOT_UID_FOR_TEST) != 0) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    return errCode;
}

#ifdef HAS_PIN_AUTH_PART
ErrCode GetAdminAuthorizationTokenForTest(std::vector<uint8_t> &token)
{
    ErrCode errCode = ERR_OK;
    auto pinInputer = std::make_shared<TestPinInputer>();
    bool inputerRegistered = false;
    do {
        errCode = AccountIAMClient::GetInstance().RegisterPINInputer(pinInputer);
        if (errCode != ERR_OK) {
            break;
        }
        inputerRegistered = true;

        std::string adminName;
        errCode = OsAccountManager::GetOsAccountNameById(Constants::START_USER_ID, adminName);
        if (errCode != ERR_OK) {
            break;
        }

        if (adminName.empty()) {
            OsAccountManager::SetOsAccountName(Constants::START_USER_ID, "test");
            OsAccountManager::GetOsAccountNameById(Constants::START_USER_ID, adminName);
        }

        std::vector<uint8_t> challenge = {1, 2, 3, 4};
        auto callback = std::make_shared<TestAdminAuthorizationCallback>();
        errCode = AuthorizationClient::GetInstance().AcquireAdminAuthorization(
            adminName, challenge, callback, "ohos.privilege.manage_local_accounts");
        if (errCode != ERR_OK) {
            break;
        }

        AdminAuthorizationResult result;
        if (!callback->WaitForResult(result)) {
            errCode = ERR_ACCOUNT_COMMON_OPERATION_TIMEOUT;
            break;
        }
        if (result.resultCode != ERR_OK && result.resultCode != ERR_IAM_NOT_ENROLLED) {
            errCode = result.resultCode;
            break;
        }
        token = std::move(result.token);
    } while (false);

    if (inputerRegistered) {
        ErrCode unregisterErrCode = AccountIAMClient::GetInstance().UnregisterPINInputer();
        if (errCode == ERR_OK && unregisterErrCode != ERR_OK) {
            errCode = unregisterErrCode;
        }
    }
    return errCode;
}

bool HasAuthorizationToken(const CreateOsAccountOptions &options)
{
    return options.token.has_value();
}

bool HasAuthorizationToken(const RemoveOsAccountOptions &options)
{
    return options.token.has_value();
}

bool HasAuthorizationToken(const CreateOsAccountForDomainOptions &options)
{
    return options.hasToken;
}

void SetAuthorizationToken(CreateOsAccountOptions &options, std::vector<uint8_t> &&token)
{
    options.token = std::move(token);
}

void SetAuthorizationToken(RemoveOsAccountOptions &options, std::vector<uint8_t> &&token)
{
    options.token = std::move(token);
}

void SetAuthorizationToken(CreateOsAccountForDomainOptions &options, std::vector<uint8_t> &&token)
{
    options.token = std::move(token);
    options.hasToken = true;
}

template<typename Options, typename Func>
ErrCode ExecuteWithAuthorizationToken(Options options, Func &&func)
{
    uint64_t oldTokenId = IPCSkeleton::GetSelfTokenID();
    uint64_t tempTokenId = 0;
    if (!AllocPermission(AUTHORIZATION_PERMISSION_LIST, tempTokenId, true)) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    ErrCode errCode = ERR_OK;
    do {
        if (!HasAuthorizationToken(options)) {
            std::vector<uint8_t> token;
            errCode = GetAdminAuthorizationTokenForTest(token);
            if (errCode != ERR_OK) {
                break;
            }
            SetAuthorizationToken(options, std::move(token));
        }
        errCode = func(options);
    } while (false);

    if (!RecoveryPermission(tempTokenId, oldTokenId)) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    return errCode;
}
#endif
#endif

ErrCode CreateOsAccountForTest(const std::string &name, const OsAccountType &type, OsAccountInfo &osAccountInfo)
{
#ifdef SUPPORT_AUTHORIZATION
#ifdef HAS_PIN_AUTH_PART
    CreateOsAccountOptions options;
    options.hasShortName = false;
    return ExecuteWithAuthorizationToken(options, [&](const CreateOsAccountOptions &authOptions) {
        return OsAccountManager::CreateOsAccount(name, name, type, authOptions, osAccountInfo);
    });
#else
    return OsAccountManager::CreateOsAccount(name, type, osAccountInfo);
#endif
#else
    return OsAccountManager::CreateOsAccount(name, type, osAccountInfo);
#endif
}

ErrCode CreateOsAccountForTest(const std::string &localName, const std::string &shortName,
    const OsAccountType &type, OsAccountInfo &osAccountInfo)
{
#ifdef SUPPORT_AUTHORIZATION
#ifdef HAS_PIN_AUTH_PART
    CreateOsAccountOptions options;
    return ExecuteWithAuthorizationToken(options, [&](const CreateOsAccountOptions &authOptions) {
        return OsAccountManager::CreateOsAccount(localName, shortName, type, authOptions, osAccountInfo);
    });
#else
    return OsAccountManager::CreateOsAccount(localName, shortName, type, osAccountInfo);
#endif
#else
    return OsAccountManager::CreateOsAccount(localName, shortName, type, osAccountInfo);
#endif
}

ErrCode CreateOsAccountForTest(const std::string &localName, const std::string &shortName,
    const OsAccountType &type, const CreateOsAccountOptions &options, OsAccountInfo &osAccountInfo)
{
#ifdef SUPPORT_AUTHORIZATION
#ifdef HAS_PIN_AUTH_PART
    return ExecuteWithAuthorizationToken(options, [&](const CreateOsAccountOptions &authOptions) {
        return OsAccountManager::CreateOsAccount(localName, shortName, type, authOptions, osAccountInfo);
    });
#else
    return OsAccountManager::CreateOsAccount(localName, shortName, type, options, osAccountInfo);
#endif
#else
    return OsAccountManager::CreateOsAccount(localName, shortName, type, options, osAccountInfo);
#endif
}

ErrCode CreateOsAccountWithFullInfoForTest(OsAccountInfo &osAccountInfo, const CreateOsAccountOptions &options)
{
#ifdef SUPPORT_AUTHORIZATION
#ifdef HAS_PIN_AUTH_PART
    return ExecuteWithAuthorizationToken(options, [&](const CreateOsAccountOptions &authOptions) {
        return OsAccountManager::CreateOsAccountWithFullInfo(osAccountInfo, authOptions);
    });
#else
    return OsAccountManager::CreateOsAccountWithFullInfo(osAccountInfo, options);
#endif
#else
    return OsAccountManager::CreateOsAccountWithFullInfo(osAccountInfo, options);
#endif
}

ErrCode CreateOsAccountForDomainForTest(const OsAccountType &type, const DomainAccountInfo &domainInfo,
    const std::shared_ptr<DomainAccountCallback> &callback, const CreateOsAccountForDomainOptions &options)
{
#ifdef SUPPORT_AUTHORIZATION
#ifdef HAS_PIN_AUTH_PART
    return ExecuteWithAuthorizationToken(options, [&](const CreateOsAccountForDomainOptions &authOptions) {
        return OsAccountManager::CreateOsAccountForDomain(type, domainInfo, callback, authOptions);
    });
#else
    return OsAccountManager::CreateOsAccountForDomain(type, domainInfo, callback, options);
#endif
#else
    return OsAccountManager::CreateOsAccountForDomain(type, domainInfo, callback, options);
#endif
}

ErrCode SetOsAccountToBeRemovedForTest(int32_t localId, bool toBeRemoved)
{
#ifdef SUPPORT_AUTHORIZATION
    return ExecuteWithUid(MAINTENANCE_UID_FOR_TEST, [&]() {
        return OsAccountManager::SetOsAccountToBeRemoved(localId, toBeRemoved);
    });
#else
    return OsAccountManager::SetOsAccountToBeRemoved(localId, toBeRemoved);
#endif
}

ErrCode RemoveOsAccountForTest(int id)
{
#ifdef SUPPORT_AUTHORIZATION
#ifdef HAS_PIN_AUTH_PART
    RemoveOsAccountOptions options;
    return ExecuteWithAuthorizationToken(options, [&](const RemoveOsAccountOptions &authOptions) {
        return OsAccountManager::RemoveOsAccount(id, authOptions);
    });
#else
    return OsAccountManager::RemoveOsAccount(id);
#endif
#else
    return OsAccountManager::RemoveOsAccount(id);
#endif
}

ErrCode RemoveOsAccountForTest(int id, const RemoveOsAccountOptions &options)
{
#ifdef SUPPORT_AUTHORIZATION
#ifdef HAS_PIN_AUTH_PART
    return ExecuteWithAuthorizationToken(options, [&](const RemoveOsAccountOptions &authOptions) {
        return OsAccountManager::RemoveOsAccount(id, authOptions);
    });
#else
    return OsAccountManager::RemoveOsAccount(id, options);
#endif
#else
    return OsAccountManager::RemoveOsAccount(id, options);
#endif
}

ErrCode CreateOsAccountByProxyForTest(const std::string &name, const OsAccountType &type, OsAccountInfo &osAccountInfo)
{
#ifdef SUPPORT_AUTHORIZATION
#ifdef HAS_PIN_AUTH_PART
    CreateOsAccountOptions options;
    options.hasShortName = false;
    return ExecuteWithAuthorizationToken(options, [&](const CreateOsAccountOptions &authOptions) {
        return OsAccount::GetInstance().CreateOsAccount(name, std::string(), type, osAccountInfo, authOptions);
    });
#else
    return OsAccount::GetInstance().CreateOsAccount(name, type, osAccountInfo);
#endif
#else
    return OsAccount::GetInstance().CreateOsAccount(name, type, osAccountInfo);
#endif
}

ErrCode CreateOsAccountByProxyForTest(const std::string &localName, const std::string &shortName,
    const OsAccountType &type, OsAccountInfo &osAccountInfo, const CreateOsAccountOptions &options)
{
#ifdef SUPPORT_AUTHORIZATION
#ifdef HAS_PIN_AUTH_PART
    return ExecuteWithAuthorizationToken(options, [&](const CreateOsAccountOptions &authOptions) {
        return OsAccount::GetInstance().CreateOsAccount(localName, shortName, type, osAccountInfo, authOptions);
    });
#else
    return OsAccount::GetInstance().CreateOsAccount(localName, shortName, type, osAccountInfo, options);
#endif
#else
    return OsAccount::GetInstance().CreateOsAccount(localName, shortName, type, osAccountInfo, options);
#endif
}

ErrCode RemoveOsAccountByProxyForTest(int id)
{
#ifdef SUPPORT_AUTHORIZATION
#ifdef HAS_PIN_AUTH_PART
    RemoveOsAccountOptions options;
    return ExecuteWithAuthorizationToken(options, [&](const RemoveOsAccountOptions &authOptions) {
        return OsAccount::GetInstance().RemoveOsAccount(id, authOptions);
    });
#else
    return OsAccount::GetInstance().RemoveOsAccount(id);
#endif
#else
    return OsAccount::GetInstance().RemoveOsAccount(id);
#endif
}

ErrCode RemoveOsAccountByProxyForTest(int id, const RemoveOsAccountOptions &options)
{
#ifdef SUPPORT_AUTHORIZATION
#ifdef HAS_PIN_AUTH_PART
    return ExecuteWithAuthorizationToken(options, [&](const RemoveOsAccountOptions &authOptions) {
        return OsAccount::GetInstance().RemoveOsAccount(id, authOptions);
    });
#else
    return OsAccount::GetInstance().RemoveOsAccount(id, options);
#endif
#else
    return OsAccount::GetInstance().RemoveOsAccount(id, options);
#endif
}
} // namespace AccountSA
} // namespace OHOS
