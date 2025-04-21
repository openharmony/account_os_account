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

#include "account_log_wrapper.h"
#include "account_error_no.h"
#include "account_iam_client.h"
#include "account_iam_info.h"
#include "account_info.h"
#include "ani_common_want.h"
#include "iam_common_defines.h"
#include "napi_account_error.h"
#include "ohos.account.disributedAccount.h"
#include "ohos.account.distributedAccount.impl.hpp"
#include "ohos.account.distributedAccount.proj.hpp"
#include "ohos.account.osAccount.impl.hpp"
#include "ohos.account.osAccount.proj.hpp"
#include "ohos_account_kits.h"
#include "os_account_info.h"
#include "os_account_manager.h"
#include "user_idm_client.h"
#include "user_idm_client_defines.h"

#include "taihe/runtime.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <vector>

using namespace taihe;
using namespace OHOS;
using namespace ohos::account::osAccount;
using namespace ohos::account::distributedAccount;


namespace {
OsAccountType::key_t ConvertToOsAccountTypeKey(AccountSA::OsAccountType type)
{
    switch (type) {
        case AccountSA::OsAccountType::ADMIN:
            return OsAccountType::key_t::ADMIN;
        case AccountSA::OsAccountType::GUEST:
            return OsAccountType::key_t::GUEST;
        case AccountSA::OsAccountType::PRIVATE:
            return OsAccountType::key_t::PRIVATE;
        case AccountSA::OsAccountType::NORMAL:
        default:
            return OsAccountType::key_t::NORMAL;
    }
}

AccountSA::OsAccountType ConvertFromOsAccountTypeKey(int32_t type)
{
    switch (static_cast<OsAccountType::key_t>(type)) {
        case OsAccountType::key_t::ADMIN:
            return AccountSA::OsAccountType::ADMIN;
        case OsAccountType::key_t::GUEST:
            return AccountSA::OsAccountType::GUEST;
        case OsAccountType::key_t::PRIVATE:
            return AccountSA::OsAccountType::PRIVATE;
        case OsAccountType::key_t::NORMAL:
        default:
            return AccountSA::OsAccountType::NORMAL;
    }
}

taihe::array<taihe::string> ConvertConstraints(const std::vector<std::string>& constraints)
{
    std::vector<taihe::string> tempStrings;
    tempStrings.reserve(constraints.size());
    for (const auto& constraint : constraints) {
        tempStrings.emplace_back(taihe::string(constraint.c_str()));
    }
    return taihe::array<taihe::string>(tempStrings.data(), tempStrings.size());
}

DistributedInfo ConvertDistributedInfo()
{
    std::pair<bool, AccountSA::OhosAccountInfo> dbAccountInfo =
        AccountSA::OhosAccountKits::GetInstance().QueryOhosAccountInfo();
    if (dbAccountInfo.first) {
        return AccountSA::CreateDistributedInfoFromAccountInfo(dbAccountInfo.second);
    }
    return AccountSA::CreateDistributedInfo();
}

DomainAccountInfo ConvertDomainInfo(const OHOS::AccountSA::OsAccountInfo& innerInfo)
{
    AccountSA::DomainAccountInfo sourceInfo;
    innerInfo.GetDomainInfo(sourceInfo);
    
    return DomainAccountInfo{
        .domain = taihe::string(sourceInfo.domain_.c_str()),
        .accountName = taihe::string(sourceInfo.accountName_.c_str()),
        .accountId = !sourceInfo.accountId_.empty() ?
            taihe::optional<taihe::string>(new taihe::string(sourceInfo.accountId_.c_str())) :
            taihe::optional<taihe::string>(),
        .isAuthenticated = taihe::optional<bool>(new bool(
            sourceInfo.status_ != AccountSA::DomainAccountStatus::LOGOUT &&
            sourceInfo.status_ < AccountSA::DomainAccountStatus::LOG_END)),
        .serverConfigId = !sourceInfo.serverConfigId_.empty() ?
            taihe::optional<taihe::string>(new taihe::string(sourceInfo.serverConfigId_.c_str())) :
            taihe::optional<taihe::string>()
    };
}

OsAccountInfo ConvertOsAccountInfo(const AccountSA::OsAccountInfo& innerInfo)
{
    return OsAccountInfo{
        .localId = innerInfo.GetLocalId(),
        .localName = taihe::string(innerInfo.GetLocalName().c_str()),
        .shortName = !innerInfo.GetShortName().empty() ?
            taihe::optional<taihe::string>(new taihe::string(innerInfo.GetShortName().c_str())) :
            taihe::optional<taihe::string>(),
        .type = OsAccountType(ConvertToOsAccountTypeKey(innerInfo.GetType())),
        .constraints = ConvertConstraints(innerInfo.GetConstraints()),
        .isVerified = innerInfo.GetIsVerified(),
        .isUnlocked = innerInfo.GetIsVerified(),
        .photo = taihe::string(innerInfo.GetPhoto().c_str()),
        .createTime = innerInfo.GetCreateTime(),
        .lastLoginTime = innerInfo.GetLastLoginTime(),
        .serialNumber = innerInfo.GetSerialNumber(),
        .isActivated = innerInfo.GetIsActived(),
        .isLoggedIn = taihe::optional<bool>(new bool(innerInfo.GetIsLoggedIn())),
        .isCreateCompleted = innerInfo.GetIsCreateCompleted(),
        .distributedInfo = ConvertDistributedInfo(),
        .domainInfo = ConvertDomainInfo(innerInfo)
    };
}

AccountSA::CreateOsAccountOptions ConvertToInnerOptions(optional_view<CreateOsAccountOptions> options)
{
    AccountSA::CreateOsAccountOptions innerOptions;
    
    if (!options.has_value()) {
        return innerOptions;
    }

    const auto& opts = options.value();
    
    innerOptions.shortName = std::string(opts.shortName.data(), opts.shortName.size());
    innerOptions.hasShortName = true;

    return innerOptions;
}

inline UserIam::UserAuth::CredentialParameters ConvertToCredentialParameters(
    const ohos::account::osAccount::CredentialInfo& info)
{
    UserIam::UserAuth::CredentialParameters params;
    params.authType = static_cast<UserIam::UserAuth::AuthType>(info.credType.get_value());
    params.pinType = static_cast<UserIam::UserAuth::PinSubType>(info.credSubType.get_value());
    params.token.assign(info.token.data(), info.token.data() + info.token.size());
    return params;
}

inline ohos::account::osAccount::RequestResult ConvertToRequestResult(
    const UserIam::UserAuth::Attributes& extraInfo)
{
    ohos::account::osAccount::RequestResult result;
    uint64_t credId = 0;
    if (extraInfo.GetUint64Value(UserIam::UserAuth::Attributes::AttributeKey::ATTR_CREDENTIAL_ID, credId)) {
        result.credentialId = taihe::optional<taihe::array<uint8_t>>(
            new taihe::array<uint8_t>(reinterpret_cast<uint8_t*>(&credId), sizeof(credId))
        );
    } else {
        result.credentialId = taihe::optional<taihe::array<uint8_t>>();
    }
    return result;
}

class TaiheIDMCallbackAdapter : public AccountSA::IDMCallback {
    public:
        explicit TaiheIDMCallbackAdapter(const ohos::account::osAccount::IIdmCallback& taiheCallback)
            : taiheCallback_(taiheCallback) {}
    
        ~TaiheIDMCallbackAdapter() = default;
    
        void OnResult(int32_t result, const UserIam::UserAuth::Attributes& extraInfo) override
        {
            if (taiheCallback_.onResult.data_ptr != nullptr) {
                ohos::account::osAccount::RequestResult reqResult = ConvertToRequestResult(extraInfo);
                taiheCallback_.onResult(result, reqResult);
            }
        }
    
        void OnAcquireInfo(int32_t module, uint32_t acquireInfo,
            const UserIam::UserAuth::Attributes& extraInfo) override
        {
            if (taiheCallback_.onAcquireInfo.has_value()) {
                std::vector<uint8_t> extraDataVec;
                extraInfo.GetUint8ArrayValue(AccountSA::Attributes::AttributeKey::ATTR_EXTRA_INFO, extraDataVec);
                taihe::array_view<uint8_t> extraDataView(extraDataVec.data(), extraDataVec.size());
                taiheCallback_.onAcquireInfo.value()(module, acquireInfo, extraDataView);
            }
        }
    
    private:
        ohos::account::osAccount::IIdmCallback taiheCallback_;
};

class AccountManagerImpl {
public:
    AccountManagerImpl() {
        // Don't forget to implement the constructor.
    }

    bool TaiheIsMainOsAccount()
    {
        TH_THROW(std::runtime_error, "TaiheIsMainOsAccount not implemented");
    }

    string TaiheGetOsAccountProfilePhoto(double localId)
    {
        TH_THROW(std::runtime_error, "TaiheGetOsAccountProfilePhoto not implemented");
    }

    OsAccountType TaiheGetOsAccountType()
    {
        TH_THROW(std::runtime_error, "TaiheGetOsAccountType not implemented");
    }

    OsAccountType TaiheGetOsAccountTypeWithId(double localId)
    {
        TH_THROW(std::runtime_error, "TaiheGetOsAccountTypeWithId not implemented");
    }

    void OnActivate(string_view name, callback_view<void(double)> callback)
    {
        TH_THROW(std::runtime_error, "OnActivate not implemented");
    }

    void OnActivating(string_view name, callback_view<void(double)> callback)
    {
        TH_THROW(std::runtime_error, "OnActivating not implemented");
    }

    void OffActivate(string_view name, optional_view<callback<void(double)>> callback)
    {
        TH_THROW(std::runtime_error, "OffActivate not implemented");
    }

    void OffActivating(string_view name, optional_view<callback<void(double)>> callback)
    {
        TH_THROW(std::runtime_error, "OffActivating not implemented");
    }

    void OnSwitching(callback_view<void(OsAccountSwitchEventData const&)> callback)
    {
        TH_THROW(std::runtime_error, "OnSwitching not implemented");
    }

    void OnSwitched(callback_view<void(OsAccountSwitchEventData const&)> callback)
    {
        TH_THROW(std::runtime_error, "OnSwitched not implemented");
    }

    void OffSwitching(optional_view<callback<void(OsAccountSwitchEventData const&)>> callback)
    {
        TH_THROW(std::runtime_error, "OffSwitching not implemented");
    }

    void OffSwitched(optional_view<callback<void(OsAccountSwitchEventData const&)>> callback)
    {
        TH_THROW(std::runtime_error, "OffSwitched not implemented");
    }

    void ActivateOsAccountSync(int32_t localId) {
        TH_THROW(std::runtime_error, "ActivateOsAccountSync not implemented");
    }

    OsAccountInfo CreateOsAccountSync(string_view localName, OsAccountType type)
    {
        TH_THROW(std::runtime_error, "CreateOsAccountSync not implemented");
    }

    OsAccountInfo CreateOsAccountWithOptionSync(string_view localName, OsAccountType type,
        optional_view<CreateOsAccountOptions> options)
    {
        TH_THROW(std::runtime_error, "CreateOsAccountWithOptionSync not implemented");
    }

    void DeactivateOsAccountSync(int32_t localId)
    {
        TH_THROW(std::runtime_error, "DeactivateOsAccountSync not implemented");
    }

    array<int32_t> GetActivatedOsAccountLocalIdsSync()
    {
        TH_THROW(std::runtime_error, "GetActivatedOsAccountLocalIdsSync not implemented");
    }

    OsAccountInfo GetCurrentOsAccountSync()
    {
        TH_THROW(std::runtime_error, "GetCurrentOsAccountSync not implemented");
    }

    int32_t GetForegroundOsAccountLocalIdSync()
    {
        TH_THROW(std::runtime_error, "GetForegroundOsAccountLocalIdSync not implemented");
    }

    int32_t GetOsAccountLocalIdSync()
    {
        TH_THROW(std::runtime_error, "GetOsAccountLocalIdSync not implemented");
    }

    int32_t GetOsAccountLocalIdForUidSync(int32_t uid)
    {
        TH_THROW(std::runtime_error, "GetOsAccountLocalIdForUidSync not implemented");
    }
};

class UserIdentityManagerImpl {
public:
    UserIdentityManagerImpl() {
        // Don't forget to implement the constructor.
    }

    array<uint8_t> OpenSession()
    {
        TH_THROW(std::runtime_error, "OpenSession not implemented");
    }

    array<uint8_t> OpenSessionPromise(optional_view<int32_t> accountId)
    {
        TH_THROW(std::runtime_error, "OpenSessionPromise not implemented");
    }

    void closeSession(optional_view<int32_t> accountId)
    {
        TH_THROW(std::runtime_error, "closeSession not implemented");
    }

    array<EnrolledCredInfo> getAuthInfoSync()
    {
        TH_THROW(std::runtime_error, "getAuthInfoSync not implemented");
    }

    array<EnrolledCredInfo> getAuthInfoWithTypeCallbackSync(AuthType authType)
    {
        TH_THROW(std::runtime_error, "getAuthInfoWithTypeCallbackSync not implemented");
    }

    array<EnrolledCredInfo> getAuthInfoWithTypePromiseSync(optional_view<AuthType> authType)
    {
        TH_THROW(std::runtime_error, "getAuthInfoWithTypePromiseSync not implemented");
    }

    array<EnrolledCredInfo> getAuthInfoWithOptionsSync(optional_view<GetAuthInfoOptions> options)
    {
        TH_THROW(std::runtime_error, "getAuthInfoWithOptionsSync not implemented");
    }

    void addCredential(CredentialInfo const& info, IIdmCallback const& callback)
    {
        TH_THROW(std::runtime_error, "addCredential not implemented");
    }

    void delUser(array_view<uint8_t> token, IIdmCallback const& callback)
    {
        TH_THROW(std::runtime_error, "delUser not implemented");
    }
};

class DomainPluginImpl {
public:
    DomainPluginImpl() {
        // Don't forget to implement the constructor.
    }

    void auth(DomainAccountInfo const& domainAccountInfo, array_view<uint8_t> credential,
        IUserAuthCallback const& callback)
    {
        TH_THROW(std::runtime_error, "auth not implemented");
    }
};

class DomainAccountManagerImpl {
public:
    DomainAccountManagerImpl() {
        // Don't forget to implement the constructor.
    }

    bool isAuthenticationExpiredSync(DomainAccountInfo const& domainAccountInfo)
    {
        TH_THROW(std::runtime_error, "isAuthenticationExpiredSync not implemented");
    }
};

class IInputDataImpl {
public:
    IInputDataImpl() {
        // Don't forget to implement the constructor.
    }

    int64_t GetSpecificImplPtr()
    {
        TH_THROW(std::runtime_error, "GetSpecificImplPtr not implemented");
    }

    void onSetDataInner(AuthSubType authSubType, array_view<uint8_t> data)
    {
        TH_THROW(std::runtime_error, "onSetDataInner not implemented");
    }
};

class UserAuthImpl {
public:
    UserAuthImpl() {
        // Don't forget to implement the constructor.
    }

    array<uint8_t> authSync(array_view<uint8_t> challenge, AuthType authType,
        AuthTrustLevel authTrustLevel, IUserAuthCallback const& callback)
    {
        TH_THROW(std::runtime_error, "authSync not implemented");
    }

    array<uint8_t> authWithOptSync(array_view<uint8_t> challenge, AuthType authType,
        AuthTrustLevel authTrustLevel, AuthOptions const& options, IUserAuthCallback const& callback)
    {
        TH_THROW(std::runtime_error, "authWithOptSync not implemented");
    }

    array<uint8_t> authUser(int32_t userId, array_view<uint8_t> challenge, AuthType authType,
        AuthTrustLevel authTrustLevel, IUserAuthCallback const& callback)
    {
        TH_THROW(std::runtime_error, "authUser not implemented");
    }

    void cancelAuth(array_view<uint8_t> contextID) {
        TH_THROW(std::runtime_error, "cancelAuth not implemented");
    }

    ExecutorProperty getPropertySync(GetPropertyRequest const& request) {
        TH_THROW(std::runtime_error, "getPropertySync not implemented");
    }
};

class PINAuthImpl {
public:
    PINAuthImpl() {
        // Don't forget to implement the constructor.
    }

    void registerInputer(IInputer const& inputer)
    {
        TH_THROW(std::runtime_error, "registerInputer not implemented");
    }
};

class InputerManagerImpl {
public:
    InputerManagerImpl() {
        // Don't forget to implement the constructor.
    }
};

AccountManager getAccountManager() {
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<AccountManagerImpl, AccountManager>();
}

void registerInputer(AuthType authType, IInputer const& inputer) {
    TH_THROW(std::runtime_error, "registerInputer not implemented");
}

UserIdentityManager createUserIdentityManager() {
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<UserIdentityManagerImpl, UserIdentityManager>();
}

UserAuth createUserAuth() {
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<UserAuthImpl, UserAuth>();
}

PINAuth createPINAuth() {
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<PINAuthImpl, PINAuth>();
}
}  // namespace

TH_EXPORT_CPP_API_getAccountManager(getAccountManager);
TH_EXPORT_CPP_API_registerInputer(registerInputer);
TH_EXPORT_CPP_API_createUserIdentityManager(createUserIdentityManager);
TH_EXPORT_CPP_API_createUserAuth(createUserAuth);
TH_EXPORT_CPP_API_createPINAuth(createPINAuth);
