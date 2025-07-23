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

#include "account_error_no.h"
#include "account_iam_client.h"
#include "account_iam_info.h"
#include "account_info.h"
#include "account_log_wrapper.h"
#include "ani_common_want.h"
#include "domain_account_client.h"
#include "iam_common_defines.h"
#include "account_error_no.h"
#include "napi_account_iam_common.h"
#include "napi_account_iam_constant.h"
#include "nlohmann/json.hpp"
#include "ohos.account.distributedAccount.impl.hpp"
#include "ohos.account.distributedAccount.proj.hpp"
#include "ohos.account.osAccount.impl.hpp"
#include "taihe_distributed_account_converter.h"
#include "ohos.account.osAccount.proj.hpp"
#include "ohos_account_kits.h"
#include "os_account_info.h"
#include "os_account_manager.h"
#include "taihe/runtime.hpp"
#include "taihe_common.h"
#include "taihe_account_info.h"
#include "user_idm_client.h"
#include "user_idm_client_defines.h"

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
using OHOS::AccountSA::ACCOUNT_LABEL;

const std::string DAFAULT_STR = "";
const bool DEFAULT_BOOL = false;
const array<uint8_t> DEFAULT_ARRAY = array<uint8_t>::make(0);
const AccountSA::OsAccountType DEFAULT_ACCOUNT_TYPE = AccountSA::OsAccountType::END;
constexpr std::int32_t MAX_SUBSCRIBER_NAME_LEN = 1024;
std::mutex g_lockForOsAccountSubscribers;
std::map<AccountSA::OsAccountManager *, std::vector<AccountSA::SubscribeCBInfo *>> g_osAccountSubscribers;
constexpr int CONTEXTID_OFFSET = 8;

template <typename T> T TaiheReturn(ErrCode errCode, T result, const T defult)
{
    if (errCode != ERR_OK) {
        int32_t jsErrCode = GenerateBusinessErrorCode(errCode);
        taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        return defult;
    }
    return result;
}

template <typename T> T TaiheIAMReturn(ErrCode errCode, T result, const T defult)
{
    if (errCode != ERR_OK) {
        int32_t jsErrCode = AccountIAMConvertToJSErrCode(errCode);
        taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        return defult;
    }

    return result;
}

void SetTaiheBusinessErrorFromNativeCode(int32_t nativeErrCode)
{
    if (nativeErrCode == ERR_OK) {
        return;
    }
    int32_t jsErrCode;
    std::string errMsg;
    jsErrCode = GenerateBusinessErrorCode(nativeErrCode);
    errMsg = ConvertToJsErrMsg(jsErrCode);
    taihe::set_business_error(jsErrCode, errMsg.c_str());
}

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

taihe::array<taihe::string> ConvertConstraints(const std::vector<std::string> &constraints)
{
    std::vector<taihe::string> tempStrings;
    tempStrings.reserve(constraints.size());
    for (const auto &constraint : constraints) {
        tempStrings.emplace_back(taihe::string(constraint.c_str()));
    }
    return taihe::array<taihe::string>(taihe::copy_data_t{}, tempStrings.data(), tempStrings.size());
}

DistributedInfo ConvertDistributedInfo()
{
    std::pair<bool, AccountSA::OhosAccountInfo> dbAccountInfo =
        AccountSA::OhosAccountKits::GetInstance().QueryOhosAccountInfo();
    if (!dbAccountInfo.first) {
        ACCOUNT_LOGE("QueryOhosAccountInfo failed.");
        return AccountSA::ConvertToDistributedInfoTH(AccountSA::OhosAccountInfo{});
    }
    return AccountSA::ConvertToDistributedInfoTH(dbAccountInfo.second);
}

DomainAccountInfo ConvertDomainInfo(const OHOS::AccountSA::OsAccountInfo &innerInfo)
{
    AccountSA::DomainAccountInfo sourceInfo;
    innerInfo.GetDomainInfo(sourceInfo);

    return DomainAccountInfo{
        .domain = taihe::string(sourceInfo.domain_.c_str()),
        .accountName = taihe::string(sourceInfo.accountName_.c_str()),
        .accountId = taihe::optional<taihe::string>(std::in_place_t{}, sourceInfo.accountId_.c_str()),
        .isAuthenticated = taihe::optional<bool>(std::in_place_t{},
            (sourceInfo.status_ != AccountSA::DomainAccountStatus::LOGOUT) &&
            (sourceInfo.status_ < AccountSA::DomainAccountStatus::LOG_END)),
        .serverConfigId = taihe::optional<taihe::string>(std::in_place_t{}, sourceInfo.serverConfigId_.c_str())};
}

OsAccountInfo ConvertOsAccountInfo(const AccountSA::OsAccountInfo &innerInfo)
{
    return OsAccountInfo{
        .localId = innerInfo.GetLocalId(),
        .localName = taihe::string(innerInfo.GetLocalName().c_str()),
        .shortName =
            taihe::optional<taihe::string>(std::in_place_t{}, innerInfo.GetShortName().c_str()),
        .type = OsAccountType(ConvertToOsAccountTypeKey(innerInfo.GetType())),
        .constraints = ConvertConstraints(innerInfo.GetConstraints()),
        .isUnlocked = innerInfo.GetIsVerified(),
        .photo = taihe::string(innerInfo.GetPhoto().c_str()),
        .createTime = innerInfo.GetCreateTime(),
        .lastLoginTime = innerInfo.GetLastLoginTime(),
        .serialNumber = innerInfo.GetSerialNumber(),
        .isActivated = innerInfo.GetIsActived(),
        .isLoggedIn = taihe::optional<bool>(std::in_place_t{}, innerInfo.GetIsLoggedIn()),
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

    const auto &opts = options.value();

    innerOptions.shortName = std::string(opts.shortName.data(), opts.shortName.size());
    innerOptions.hasShortName = true;

    return innerOptions;
}

inline UserIam::UserAuth::CredentialParameters ConvertToCredentialParameters(
    const ohos::account::osAccount::CredentialInfo &info)
{
    UserIam::UserAuth::CredentialParameters params;
    params.authType = static_cast<UserIam::UserAuth::AuthType>(info.credType.get_value());
    params.pinType = static_cast<UserIam::UserAuth::PinSubType>(info.credSubType.get_value());
    params.token.assign(info.token.data(), info.token.data() + info.token.size());
    return params;
}

inline ohos::account::osAccount::RequestResult ConvertToRequestResult(const UserIam::UserAuth::Attributes &extraInfo)
{
    ohos::account::osAccount::RequestResult result;
    uint64_t credId = 0;
    if (extraInfo.GetUint64Value(UserIam::UserAuth::Attributes::AttributeKey::ATTR_CREDENTIAL_ID, credId)) {
        result.credentialId = taihe::optional<taihe::array<uint8_t>>(
            std::in_place_t{}, taihe::copy_data_t{}, reinterpret_cast<uint8_t *>(&credId), sizeof(credId));
    } else {
        result.credentialId = taihe::optional<taihe::array<uint8_t>>();
    }
    return result;
}

class TaiheIDMCallbackAdapter : public AccountSA::IDMCallback {
public:
    explicit TaiheIDMCallbackAdapter(const ohos::account::osAccount::IIdmCallback &taiheCallback)
        : taiheCallback_(taiheCallback)
    {
    }

    ~TaiheIDMCallbackAdapter() = default;

    void OnResult(int32_t result, const UserIam::UserAuth::Attributes &extraInfo) override
    {
        ohos::account::osAccount::RequestResult reqResult = ConvertToRequestResult(extraInfo);
        taiheCallback_.onResult(result, reqResult);
    }

    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const UserIam::UserAuth::Attributes &extraInfo) override
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

class THCreateDomainCallback : public AccountSA::DomainAccountCallback {
public:
    int32_t errCode_ = -1;
    std::mutex mutex_;
    std::condition_variable cv_;
    AccountSA::OsAccountInfo osAccountInfos_;
    bool onResultCalled_ = false;

    void OnResult(const int32_t errorCode, Parcel &parcel)
    {
        std::shared_ptr<AccountSA::OsAccountInfo> osAccountInfo(AccountSA::OsAccountInfo::Unmarshalling(parcel));
        if (osAccountInfo == nullptr) {
            ACCOUNT_LOGE("failed to unmarshalling OsAccountInfo");
            return;
        }
        std::unique_lock<std::mutex> lock(mutex_);
        if (this->onResultCalled_) {
            return;
        }
        this->onResultCalled_ = true;
        this->osAccountInfos_ = *osAccountInfo;
        this->errCode_ = errorCode;
        cv_.notify_one();
    }
};

class AccountManagerImpl {
private:
    AccountSA::OsAccountManager *osAccountManger_ = nullptr;

public:
    AccountManagerImpl()
    {
        osAccountManger_ = new (std::nothrow) AccountSA::OsAccountManager();
    }

    ~AccountManagerImpl()
    {
        if (osAccountManger_ != nullptr) {
            delete osAccountManger_;
            osAccountManger_ = nullptr;
        }
    }

    bool IsMainOsAccountSync()
    {
        bool isMainOsAcount = false;
        ErrCode errCode = AccountSA::OsAccountManager::IsMainOsAccount(isMainOsAcount);
        return TaiheReturn(errCode, isMainOsAcount, DEFAULT_BOOL);
    }

    string GetOsAccountProfilePhotoSync(int32_t localId)
    {
        int32_t temp = localId;
        std::string photo = "";
        ErrCode errCode = AccountSA::OsAccountManager::GetOsAccountProfilePhoto(temp, photo);
        return TaiheReturn(errCode, photo, DAFAULT_STR);
    }

    OsAccountType GetOsAccountTypeSync()
    {
        AccountSA::OsAccountType type = DEFAULT_ACCOUNT_TYPE;
        ErrCode errCode = AccountSA::OsAccountManager::GetOsAccountTypeFromProcess(type);
        return ConvertToOsAccountTypeKey(TaiheReturn(errCode, type, DEFAULT_ACCOUNT_TYPE));
    }

    OsAccountType GetOsAccountTypeWithIdSync(int32_t localId)
    {
        AccountSA::OsAccountType type = DEFAULT_ACCOUNT_TYPE;
        int32_t temp = localId;
        ErrCode errCode = AccountSA::OsAccountManager::GetOsAccountType(temp, type);
        return ConvertToOsAccountTypeKey(TaiheReturn(errCode, type, DEFAULT_ACCOUNT_TYPE));
    }

    static bool IsSubscribedInMap(AccountSA::SubscribeCBInfo *subscribeCBInfo)
    {
        std::lock_guard<std::mutex> lock(g_lockForOsAccountSubscribers);
        auto subscribe = g_osAccountSubscribers.find(subscribeCBInfo->osManager);
        if (subscribe == g_osAccountSubscribers.end()) {
            ACCOUNT_LOGE("Not find osManager!");
            return false;
        }
        auto it = subscribe->second.begin();
        while (it != subscribe->second.end()) {
            if ((*it)->IsSameCallBack(subscribeCBInfo->osSubscribeType, subscribeCBInfo->activeCallbackRef,
                                      subscribeCBInfo->switchCallbackRef)) {
                ACCOUNT_LOGE("Is same callback!");
                return true;
            }
            it++;
        }
        return false;
    }

    void Subsribe(std::string name, AccountSA::OS_ACCOUNT_SUBSCRIBE_TYPE type,
                  std::shared_ptr<active_callback> activeCallback, std::shared_ptr<switch_callback> switchCallback)
    {
        AccountSA::SubscribeCBInfo *subscribeCBInfo = new (std::nothrow) AccountSA::SubscribeCBInfo();
        if (subscribeCBInfo == nullptr) {
            ACCOUNT_LOGE("insufficient memory for subscribeCBInfo!");
            return;
        }
        subscribeCBInfo->activeCallbackRef = activeCallback;
        subscribeCBInfo->switchCallbackRef = switchCallback;
        AccountSA::OsAccountSubscribeInfo subscribeInfo(type, name);
        subscribeCBInfo->subscriber = std::make_shared<AccountSA::TaiheSubscriberPtr>(subscribeInfo);
        subscribeCBInfo->subscriber->activeRef_ = activeCallback;
        subscribeCBInfo->subscriber->switchRef_ = switchCallback;
        subscribeCBInfo->osManager = osAccountManger_;
        subscribeCBInfo->osSubscribeType = type;
        if (IsSubscribedInMap(subscribeCBInfo)) {
            ACCOUNT_LOGE("Has in map.");
            delete subscribeCBInfo;
            return;
        }
        ErrCode errCode = AccountSA::OsAccountManager::SubscribeOsAccount(subscribeCBInfo->subscriber);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("SubscribeOsAccount return error.");
            delete subscribeCBInfo;
            int32_t jsErrCode = GenerateBusinessErrorCode(errCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
            return;
        } else {
            std::lock_guard<std::mutex> lock(g_lockForOsAccountSubscribers);
            g_osAccountSubscribers[osAccountManger_].emplace_back(subscribeCBInfo);
        }
    }

    void Unsubscribe(std::string unsubscribeName, AccountSA::OS_ACCOUNT_SUBSCRIBE_TYPE type,
                     std::shared_ptr<active_callback> activeCallback, std::shared_ptr<switch_callback> switchCallback)
    {
        std::lock_guard<std::mutex> lock(g_lockForOsAccountSubscribers);
        auto subscribe = g_osAccountSubscribers.find(osAccountManger_);
        if (subscribe == g_osAccountSubscribers.end()) {
            return;
        }
        auto item = subscribe->second.begin();
        while (item != subscribe->second.end()) {
            AccountSA::OsAccountSubscribeInfo subscribeInfo;
            AccountSA::OS_ACCOUNT_SUBSCRIBE_TYPE osSubscribeType;
            std::string name;
            (*item)->subscriber->GetSubscribeInfo(subscribeInfo);
            subscribeInfo.GetOsAccountSubscribeType(osSubscribeType);
            subscribeInfo.GetName(name);
            if (((type != osSubscribeType) || (unsubscribeName != name))) {
                item++;
                continue;
            }
            if ((activeCallback != nullptr || switchCallback != nullptr) &&
                !((*item)->IsSameCallBack(type, activeCallback, switchCallback))) {
                item++;
                continue;
            }
            int errCode = AccountSA::OsAccountManager::UnsubscribeOsAccount((*item)->subscriber);
            if (errCode != ERR_OK) {
                int32_t jsErrCode = GenerateBusinessErrorCode(errCode);
                taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
                return;
            }
            delete (*item);
            item = subscribe->second.erase(item);
            if (activeCallback != nullptr || switchCallback != nullptr) {
                break;
            }
        }
        if (subscribe->second.empty()) {
            g_osAccountSubscribers.erase(subscribe->first);
        }
    }

    void on(string_view type, string_view name, callback_view<void(int32_t)> callback)
    {
        if (type.size() == 0 || (type != "activate" && type != "activating")) {
            ACCOUNT_LOGE("Subscriber name size %{public}zu is invalid.", name.size());
            std::string errMsg =
                "Parameter error. The content of \"type\" must be \"activate|activating|switched|switching\"";
            taihe::set_business_error(ERR_JS_INVALID_PARAMETER, errMsg);
            return;
        }
        if (name.size() == 0 || name.size() > MAX_SUBSCRIBER_NAME_LEN) {
            ACCOUNT_LOGE("Subscriber name size %{public}zu is invalid.", name.size());
            std::string errMsg = "Parameter error. The length of \"name\" is invalid";
            taihe::set_business_error(ERR_JS_INVALID_PARAMETER, errMsg);
            return;
        }
        active_callback call = callback;
        Subsribe(name.data(),
                 type == "activate" ? AccountSA::OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATED
                                    : AccountSA::OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATING,
                 std::make_shared<active_callback>(call), nullptr);
    }

    void off(string_view type, string_view name, optional_view<callback<void(int32_t)>> callback)
    {
        if (type.size() == 0 || (type != "activate" && type != "activating")) {
            ACCOUNT_LOGE("Subscriber name size %{public}zu is invalid.", name.size());
            std::string errMsg =
                "Parameter error. The content of \"type\" must be \"activate|activating|switched|switching\"";
            taihe::set_business_error(ERR_JS_INVALID_PARAMETER, errMsg);
            return;
        }
        if (name.size() == 0 || name.size() > MAX_SUBSCRIBER_NAME_LEN) {
            ACCOUNT_LOGE("Subscriber name size %{public}zu is invalid.", name.size());
            std::string errMsg = "Parameter error. The length of \"name\" is invalid";
            taihe::set_business_error(ERR_JS_INVALID_PARAMETER, errMsg);
            return;
        }
        std::shared_ptr<active_callback> activeCallback = nullptr;
        if (callback) {
            active_callback call = *callback;
            activeCallback = std::make_shared<active_callback>(call);
        }
        Unsubscribe(name.data(),
                    type == "activate" ? AccountSA::OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATED
                                       : AccountSA::OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATING,
                    activeCallback, nullptr);
    }

    void OnSwitching(callback_view<void(OsAccountSwitchEventData const &)> callback)
    {
        switch_callback call = callback;
        Subsribe("", AccountSA::OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHING, nullptr, std::make_shared<switch_callback>(call));
    }

    void OnSwitched(callback_view<void(OsAccountSwitchEventData const &)> callback)
    {
        switch_callback call = callback;
        Subsribe("", AccountSA::OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHED, nullptr, std::make_shared<switch_callback>(call));
    }

    void OffSwitching(optional_view<callback<void(OsAccountSwitchEventData const &)>> callback)
    {
        std::shared_ptr<switch_callback> switchCallback = nullptr;
        if (callback) {
            switch_callback call = *callback;
            switchCallback = std::make_shared<switch_callback>(call);
        }
        Unsubscribe("", AccountSA::OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHING, nullptr, switchCallback);
    }

    void OffSwitched(optional_view<callback<void(OsAccountSwitchEventData const &)>> callback)
    {
        std::shared_ptr<switch_callback> switchCallback = nullptr;
        if (callback) {
            switch_callback call = *callback;
            switchCallback = std::make_shared<switch_callback>(call);
        }
        Unsubscribe("", AccountSA::OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHED, nullptr, switchCallback);
    }

    void ActivateOsAccountSync(int32_t localId)
    {
        ErrCode errCode = AccountSA::OsAccountManager::ActivateOsAccount(localId);
        ACCOUNT_LOGI("ActivateOsAccount returned errCode: %{public}d", errCode);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("ActivateOsAccount failed with errCode: %{public}d", errCode);
            SetTaiheBusinessErrorFromNativeCode(errCode);
        }
    }

    OsAccountInfo CreateOsAccountSync(string_view localName, OsAccountType type)
    {
        AccountSA::OsAccountInfo innerInfo;
        std::string name(localName.data(), localName.size());
        AccountSA::OsAccountType innerType = ConvertFromOsAccountTypeKey(type.get_value());

        ErrCode errCode = AccountSA::OsAccountManager::CreateOsAccount(name, innerType, innerInfo);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("CreateOsAccount failed with errCode: %{public}d", errCode);
            SetTaiheBusinessErrorFromNativeCode(errCode);
        }
        OsAccountInfo info = ConvertOsAccountInfo(innerInfo);
        return info;
    }

    OsAccountInfo CreateOsAccountWithOptionSync(string_view localName, OsAccountType type,
                                                optional_view<CreateOsAccountOptions> options)
    {
        AccountSA::OsAccountInfo innerInfo;
        std::string name(localName.data(), localName.size());
        AccountSA::OsAccountType innerType = ConvertFromOsAccountTypeKey(type.get_value());

        if (options.has_value()) {
            const auto &opts = options.value();
            std::string shortName(opts.shortName.data(), opts.shortName.size());

            AccountSA::CreateOsAccountOptions innerOptions = ConvertToInnerOptions(options);
            ErrCode errCode =
                AccountSA::OsAccountManager::CreateOsAccount(name, shortName, innerType, innerOptions, innerInfo);
            if (errCode != ERR_OK) {
                SetTaiheBusinessErrorFromNativeCode(errCode);
            }
        } else {
            ErrCode errCode = AccountSA::OsAccountManager::CreateOsAccount(name, innerType, innerInfo);
            if (errCode != ERR_OK) {
                SetTaiheBusinessErrorFromNativeCode(errCode);
            }
        }
        OsAccountInfo info = ConvertOsAccountInfo(innerInfo);
        return info;
    }

    void DeactivateOsAccountSync(int32_t localId)
    {
        ErrCode errCode = AccountSA::OsAccountManager::DeactivateOsAccount(localId);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("DeactivateOsAccount failed with errCode: %{public}d", errCode);
            SetTaiheBusinessErrorFromNativeCode(errCode);
        }
    }

    array<int32_t> GetActivatedOsAccountLocalIdsSync()
    {
        std::vector<int32_t> ids;
        ErrCode errCode = AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
        if (errCode != ERR_OK || ids.empty()) {
            SetTaiheBusinessErrorFromNativeCode(errCode);
            return taihe::array<int32_t>(nullptr, 0);
        }
        return taihe::array<int32_t>(taihe::copy_data_t{}, ids.data(), ids.size());
    }

    OsAccountInfo QueryOsAccountSync()
    {
        AccountSA::OsAccountInfo innerInfo;
        if (AccountSA::AccountPermissionManager::CheckSystemApp(false) != ERR_OK) {
            SetTaiheBusinessErrorFromNativeCode(ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR);
            return ConvertOsAccountInfo(innerInfo);
        }
        ErrCode errCode = AccountSA::OsAccountManager::QueryCurrentOsAccount(innerInfo);
        if (errCode != ERR_OK) {
            int32_t jsErrCode = (errCode == ERR_ACCOUNT_COMMON_PERMISSION_DENIED)
                                    ? ERR_OSACCOUNT_KIT_QUERY_CURRENT_OS_ACCOUNT_ERROR
                                    : errCode;
            ACCOUNT_LOGE("QueryCurrentOsAccount failed with errCode: %{public}d", jsErrCode);
            SetTaiheBusinessErrorFromNativeCode(jsErrCode);
            return ConvertOsAccountInfo(innerInfo);
        }
        return ConvertOsAccountInfo(innerInfo);
    }

    int32_t GetForegroundOsAccountLocalIdSync()
    {
        int32_t id = -1;
        ErrCode errCode = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(id);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("GetForegroundOsAccountLocalId failed with errCode: %{public}d", errCode);
            SetTaiheBusinessErrorFromNativeCode(errCode);
        }
        return id;
    }

    int32_t GetOsAccountLocalIdSync()
    {
        int32_t id = -1;
        ErrCode errCode = AccountSA::OsAccountManager::GetOsAccountLocalIdFromProcess(id);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("GetOsAccountLocalIdFromProcess failed with errCode: %{public}d", errCode);
            SetTaiheBusinessErrorFromNativeCode(errCode);
        }
        return id;
    }

    int32_t GetOsAccountLocalIdForUidSync(int32_t uid)
    {
        int32_t id = -1;
        ErrCode errCode = AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, id);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("GetOsAccountLocalIdFromUid failed with errCode: %{public}d", errCode);
            SetTaiheBusinessErrorFromNativeCode(errCode);
        }
        return id;
    }

    bool IsOsAccountUnlockedSync()
    {
        bool isUnlocked = false;
        ErrCode errCode = AccountSA::OsAccountManager::IsCurrentOsAccountVerified(isUnlocked);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("IsOsAccountUnlocked failed with errCode: %{public}d", errCode);
            SetTaiheBusinessErrorFromNativeCode(errCode);
        }
        return isUnlocked;
    }

    bool IsOsAccountUnlockedById(int32_t localId)
    {
        if (AccountSA::AccountPermissionManager::CheckSystemApp(false) != ERR_OK) {
            SetTaiheBusinessErrorFromNativeCode(ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR);
            return false;
        }
        bool isUnlocked = false;
        ErrCode errCode = AccountSA::OsAccountManager::IsOsAccountVerified(localId, isUnlocked);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("IsOsAccountUnlocked failed with errCode: %{public}d", errCode);
            SetTaiheBusinessErrorFromNativeCode(errCode);
        }
        return isUnlocked;
    }

    array<OsAccountInfo> QueryAllCreatedOsAccountsSync()
    {
        std::vector<AccountSA::OsAccountInfo> osAccountInfos;
        ErrCode errCode = AccountSA::OsAccountManager::QueryAllCreatedOsAccounts(osAccountInfos);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("QueryAllCreatedOsAccounts failed with errCode: %{public}d", errCode);
            SetTaiheBusinessErrorFromNativeCode(errCode);
        }
        std::vector<OsAccountInfo> convertedInfos;
        convertedInfos.reserve(osAccountInfos.size());
        for (const auto &info : osAccountInfos) {
            convertedInfos.push_back(ConvertOsAccountInfo(info));
        }

        return taihe::array<OsAccountInfo>(taihe::copy_data_t{}, convertedInfos.data(), convertedInfos.size());
    }

    int32_t QueryMaxLoggedInOsAccountNumberSync()
    {
        uint32_t maxLoggedInNumber = 0;
        ErrCode errCode = AccountSA::OsAccountManager::QueryMaxLoggedInOsAccountNumber(maxLoggedInNumber);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("QueryMaxLoggedInOsAccountNumber failed with errCode: %{public}d", errCode);
            SetTaiheBusinessErrorFromNativeCode(errCode);
        }
        return static_cast<int32_t>(maxLoggedInNumber);
    }

    OsAccountInfo QueryOsAccountByIdSync(int32_t localId)
    {
        AccountSA::OsAccountInfo osAccountInfo;
        ErrCode errCode = AccountSA::OsAccountManager::QueryOsAccountById(localId, osAccountInfo);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("QueryOsAccountById failed with errCode: %{public}d", errCode);
            SetTaiheBusinessErrorFromNativeCode(errCode);
        }
        return ConvertOsAccountInfo(osAccountInfo);
    }

    AccountSA::DomainAccountInfo ConvertToDomainAccountInfoInner(const ohos::account::osAccount::DomainAccountInfo
        &domainAccountInfo)
    {
        AccountSA::DomainAccountInfo domainAccountInfoInner(std::string(domainAccountInfo.domain.c_str()),
                                                            std::string(domainAccountInfo.accountName.c_str()));
        if (domainAccountInfo.accountId.has_value()) {
            domainAccountInfoInner.accountId_ = domainAccountInfo.accountId.value();
        }
        if (domainAccountInfo.serverConfigId.has_value()) {
            domainAccountInfoInner.serverConfigId_ = domainAccountInfo.serverConfigId.value();
        }
        return domainAccountInfoInner;
    }

    OsAccountInfo CreateOsAccountForDomainSync(OsAccountType type, DomainAccountInfo const& domainInfo)
    {
        AccountSA::OsAccountType innerType = ConvertFromOsAccountTypeKey(type.get_value());
        AccountSA::DomainAccountInfo innerDomainAccountInfo = ConvertToDomainAccountInfoInner(domainInfo);
        std::shared_ptr<THCreateDomainCallback> createDomainCallback = std::make_shared<THCreateDomainCallback>();
        AccountSA::CreateOsAccountForDomainOptions innerOptions;
        ErrCode errCode = AccountSA::OsAccountManager::CreateOsAccountForDomain(innerType, innerDomainAccountInfo,
            createDomainCallback, innerOptions);;
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("CreateOsAccountForDomainSync failed with errCode: %{public}d", errCode);
            SetTaiheBusinessErrorFromNativeCode(errCode);
            return ConvertOsAccountInfo(createDomainCallback->osAccountInfos_);
        }
        std::unique_lock<std::mutex> lock(createDomainCallback->mutex_);
        createDomainCallback->cv_.wait(lock, [createDomainCallback] { return createDomainCallback->onResultCalled_;});
        if (createDomainCallback->errCode_ != ERR_OK) {
            ACCOUNT_LOGE("CreateOsAccountForDomainSync failed with errCode: %{public}d",
                createDomainCallback->errCode_);
            SetTaiheBusinessErrorFromNativeCode(createDomainCallback->errCode_);
        }
        return ConvertOsAccountInfo(createDomainCallback->osAccountInfos_);
    }

    OsAccountInfo CreateOsAccountForDomainWithOpts(OsAccountType type, DomainAccountInfo const& domainInfo,
        optional_view<ohos::account::osAccount::CreateOsAccountForDomainOptions> const& options)
    {
        AccountSA::OsAccountType innerType = ConvertFromOsAccountTypeKey(type.get_value());
        AccountSA::DomainAccountInfo innerDomainAccountInfo = ConvertToDomainAccountInfoInner(domainInfo);
        AccountSA::CreateOsAccountForDomainOptions innerOptions;
        innerOptions.hasShortName = false;
        if (options.has_value() && options.value().options.shortName != "") {
            std::string innerShortName(options.value().options.shortName.data(),
                options.value().options.shortName.size());
            innerOptions.shortName = innerShortName;
            innerOptions.hasShortName = true;
        }
        std::shared_ptr<THCreateDomainCallback> createDomainCallback = std::make_shared<THCreateDomainCallback>();
        ErrCode errCode = AccountSA::OsAccountManager::CreateOsAccountForDomain(innerType, innerDomainAccountInfo,
            createDomainCallback, innerOptions);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("CreateOsAccountForDomainWithOpts failed with errCode: %{public}d", errCode);
            SetTaiheBusinessErrorFromNativeCode(errCode);
            return ConvertOsAccountInfo(createDomainCallback->osAccountInfos_);
        }
        std::unique_lock<std::mutex> lock(createDomainCallback->mutex_);
        createDomainCallback->cv_.wait(lock, [createDomainCallback] { return createDomainCallback->onResultCalled_;});
        if (createDomainCallback->errCode_ != ERR_OK) {
            ACCOUNT_LOGE("CreateOsAccountForDomainWithOpts failed with errCode: %{public}d",
                createDomainCallback->errCode_);
            SetTaiheBusinessErrorFromNativeCode(createDomainCallback->errCode_);
        }
        return ConvertOsAccountInfo(createDomainCallback->osAccountInfos_);
    }
};

AuthType ConvertToAuthTypeTH(const AccountSA::AuthType &type)
{
    switch (type) {
        case AccountSA::AuthType::PIN:
            return AuthType(AuthType::key_t::PIN);
        case AccountSA::AuthType::FACE:
            return AuthType(AuthType::key_t::FACE);
        case AccountSA::AuthType::FINGERPRINT:
            return AuthType(AuthType::key_t::FINGERPRINT);
        case AccountSA::AuthType::RECOVERY_KEY:
            return AuthType(AuthType::key_t::RECOVERY_KEY);
        case AccountSA::IAMAuthType::DOMAIN:
            return AuthType(AuthType::key_t::DOMAIN);
        default:
            SetTaiheBusinessErrorFromNativeCode(ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR);
            return AuthType(AuthType::key_t::INVALID);
    }
}

AuthSubType ConvertToAuthSubTypeTH(const AccountSA::PinSubType &type)
{
    switch (type) {
        case AccountSA::PinSubType::PIN_SIX:
            return AuthSubType(AuthSubType::key_t::PIN_SIX);
        case AccountSA::PinSubType::PIN_NUMBER:
            return AuthSubType(AuthSubType::key_t::PIN_NUMBER);
        case AccountSA::PinSubType::PIN_MIXED:
            return AuthSubType(AuthSubType::key_t::PIN_MIXED);
        case AccountSA::PinSubType::PIN_FOUR:
            return AuthSubType(AuthSubType::key_t::PIN_FOUR);
        case AccountSA::PinSubType::PIN_PATTERN:
            return AuthSubType(AuthSubType::key_t::PIN_PATTERN);
        case AccountSA::PinSubType::PIN_QUESTION:
            return AuthSubType(AuthSubType::key_t::PIN_QUESTION);
        case AccountJsKit::AuthSubType::FACE_2D:
            return AuthSubType(AuthSubType::key_t::FACE_2D);
        case AccountJsKit::AuthSubType::FACE_3D:
            return AuthSubType(AuthSubType::key_t::FACE_3D);
        case AccountJsKit::AuthSubType::FINGERPRINT_CAPACITIVE:
            return AuthSubType(AuthSubType::key_t::FINGERPRINT_CAPACITIVE);
        case AccountJsKit::AuthSubType::FINGERPRINT_OPTICAL:
            return AuthSubType(AuthSubType::key_t::FINGERPRINT_OPTICAL);
        case AccountJsKit::AuthSubType::FINGERPRINT_ULTRASONIC:
            return AuthSubType(AuthSubType::key_t::FINGERPRINT_ULTRASONIC);
        case AccountSA::IAMAuthSubType::DOMAIN_MIXED:
            return AuthSubType(AuthSubType::key_t::DOMAIN_MIXED);
    }
    return AuthSubType(AuthSubType::key_t::INVALID);
}

std::vector<EnrolledCredInfo> ConvertCredentialInfoArray(const std::vector<AccountSA::CredentialInfo> &infoList)
{
    std::vector<EnrolledCredInfo> result;
    for (auto each : infoList) {
        EnrolledCredInfo info{
            .credentialId = taihe::array<uint8_t>(taihe::copy_data_t{}, reinterpret_cast<uint8_t *>(&each.credentialId),
                                                  sizeof(uint64_t)),
            .templateId = taihe::array<uint8_t>(taihe::copy_data_t{}, reinterpret_cast<uint8_t *>(&each.templateId),
                                                sizeof(uint64_t)),
            .authType = ConvertToAuthTypeTH(each.authType),
            .authSubType = ConvertToAuthSubTypeTH(each.pinType.value_or(AccountJsKit::PinSubType::PIN_MAX)),
        };
        result.emplace_back(info);
    }
    return result;
}

class THGetInfoCallback : public AccountSA::GetCredInfoCallback {
public:
    void OnCredentialInfo(int32_t retCode, const std::vector<AccountSA::CredentialInfo> &infoList) override
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (this->onResultCalled) {
            return;
        }
        onResultCalled = true;
        if (retCode != ERR_OK) {
            this->result = retCode;
            return;
        }
        this->result = ERR_OK;
        this->infoList = ConvertCredentialInfoArray(infoList);
        cv.notify_one();
    }
    int32_t result = -1;
    std::vector<EnrolledCredInfo> infoList;
    std::mutex mutex;
    std::condition_variable cv;
    bool onResultCalled = false;
};

class UserIdentityManagerImpl {
public:
    UserIdentityManagerImpl() {}

    array<uint8_t> OpenSession()
    {
        return OpenSessionPromise(nullptr);
    }

    array<uint8_t> OpenSessionPromise(optional_view<int32_t> accountId)
    {
        ErrCode errCode = ERR_OK;
        int32_t userId = -1;
        if (accountId) {
            userId = *accountId;
        }
        if (accountId && !OHOS::AccountSA::IsAccountIdValid(userId)) {
            taihe::set_business_error(ERR_JS_ACCOUNT_NOT_FOUND, ConvertToJsErrMsg(ERR_JS_ACCOUNT_NOT_FOUND));
            return DEFAULT_ARRAY;
        }
        std::vector<uint8_t> challenge;
        array<uint8_t> result = DEFAULT_ARRAY;
        errCode = AccountSA::AccountIAMClient::GetInstance().OpenSession(userId, challenge);
        if (errCode == ERR_OK) {
            result = taihe::array<uint8_t>(taihe::copy_data_t{}, challenge.data(), challenge.size());
        }

        return TaiheIAMReturn(errCode, result, DEFAULT_ARRAY);
    }

    void CloseSession(optional_view<int32_t> accountId)
    {
        if (accountId.has_value() && !AccountSA::IsAccountIdValid(accountId.value())) {
            SetTaiheBusinessErrorFromNativeCode(ERR_JS_ACCOUNT_NOT_FOUND);
            return;
        }
        int32_t localId = accountId.value_or(-1);
        ErrCode errCode = AccountSA::AccountIAMClient::GetInstance().CloseSession(localId);
        if (errCode != ERR_OK) {
            int32_t jsErrCode = AccountIAMConvertToJSErrCode(errCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        return;
    }

    ErrCode GetAuthInfoTHInner(const int32_t userId, const AccountSA::AuthType authType,
                               std::vector<EnrolledCredInfo> &infos)
    {
        std::shared_ptr<THGetInfoCallback> idmCallback = std::make_shared<THGetInfoCallback>();
        AccountSA::AccountIAMClient::GetInstance().GetCredentialInfo(userId, authType, idmCallback);
        std::unique_lock<std::mutex> lock(idmCallback->mutex);
        idmCallback->cv.wait(lock, [idmCallback] { return idmCallback->onResultCalled; });
        infos = idmCallback->infoList;
        return idmCallback->result;
    }

    array<EnrolledCredInfo> GetAuthInfoEmpty()
    {
        int32_t userId = -1;
        AccountSA::AuthType authTypeInner;
        std::vector<EnrolledCredInfo> infos;
        ErrCode errCode = GetAuthInfoTHInner(userId, authTypeInner, infos);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("GetAuthInfoTHInner failed with errCode: %{public}d", errCode);
            int32_t jsErrCode = AccountIAMConvertToJSErrCode(errCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
            std::vector<EnrolledCredInfo> emptyArr;
            return taihe::array<EnrolledCredInfo>(taihe::copy_data_t{}, emptyArr.data(), emptyArr.size());
        }
        return taihe::array<EnrolledCredInfo>(taihe::copy_data_t{}, infos.data(), infos.size());
    }

    array<EnrolledCredInfo> GetAuthInfoType(AuthType authType)
    {
        int32_t userId = -1;
        AccountSA::AuthType authTypeInner = static_cast<AccountSA::AuthType>(authType.get_value());
        std::vector<EnrolledCredInfo> infos;
        ErrCode errCode = GetAuthInfoTHInner(userId, authTypeInner, infos);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("GetAuthInfoTHInner failed with errCode: %{public}d", errCode);
            int32_t jsErrCode = AccountIAMConvertToJSErrCode(errCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
            std::vector<EnrolledCredInfo> emptyArr;
            return taihe::array<EnrolledCredInfo>(taihe::copy_data_t{}, emptyArr.data(), emptyArr.size());
        }
        return taihe::array<EnrolledCredInfo>(taihe::copy_data_t{}, infos.data(), infos.size());
    }

    array<EnrolledCredInfo> GetAuthInfoWithOptionsSync(const GetAuthInfoOptions &options)
    {
        int32_t userId = -1;
        std::vector<EnrolledCredInfo> infos;
        AccountSA::AuthType authTypeInner;
        if (options.authType.has_value()) {
            authTypeInner = static_cast<AccountSA::AuthType>(options.authType.value().get_value());
        }
        if (options.accountId.has_value()) {
            userId = options.accountId.value();
            if (!AccountSA::IsAccountIdValid(userId)) {
                int32_t jsErrCode = AccountIAMConvertToJSErrCode(JSErrorCode::ERR_JS_ACCOUNT_NOT_FOUND);
                taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
                std::vector<EnrolledCredInfo> emptyArr;
                return taihe::array<EnrolledCredInfo>(taihe::copy_data_t{}, emptyArr.data(), emptyArr.size());
            }
        }
        ErrCode errCode = GetAuthInfoTHInner(userId, authTypeInner, infos);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("GetAuthInfoTHInner failed with errCode: %{public}d", errCode);
            int32_t jsErrCode = AccountIAMConvertToJSErrCode(errCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
            std::vector<EnrolledCredInfo> emptyArr;
            return taihe::array<EnrolledCredInfo>(taihe::copy_data_t{}, emptyArr.data(), emptyArr.size());
        }
        return taihe::array<EnrolledCredInfo>(taihe::copy_data_t{}, infos.data(), infos.size());
    }

    void AddCredential(const CredentialInfo &info, const IIdmCallback &callback)
    {
        AccountSA::CredentialParameters innerCredInfo = ConvertToCredentialParameters(info);
        ErrCode nativeErrCode = ERR_OK;
        std::shared_ptr<AccountSA::IDMCallback> idmCallbackPtr = std::make_shared<TaiheIDMCallbackAdapter>(callback);
        UserIam::UserAuth::Attributes emptyResult;

        int32_t userId = info.accountId.value_or(-1);
        if (info.accountId.has_value() && !AccountSA::IsAccountIdValid(userId)) {
            ACCOUNT_LOGE("AddCredential failed: accountId %{public}d is invalid.", userId);
            idmCallbackPtr->OnResult(ERR_JS_ACCOUNT_NOT_FOUND, emptyResult);
            return;
        }
        AccountSA::AccountIAMClient::GetInstance().AddCredential(info.accountId.value(), innerCredInfo, idmCallbackPtr);
    }

    void UpdateCredential(const CredentialInfo &credentialInfo, const IIdmCallback &callback)
    {
        AccountSA::CredentialParameters innerCredInfo = ConvertToCredentialParameters(credentialInfo);
        std::shared_ptr<AccountSA::IDMCallback> idmCallbackPtr = std::make_shared<TaiheIDMCallbackAdapter>(callback);
        UserIam::UserAuth::Attributes emptyResult;

        if (!credentialInfo.accountId.has_value()) {
            ACCOUNT_LOGE("UpdateCredential failed: accountId is missing.");
            idmCallbackPtr->OnResult(ERR_JS_PARAMETER_ERROR, emptyResult);
            return;
        }

        int32_t userId = credentialInfo.accountId.value();
        if (!AccountSA::IsAccountIdValid(userId)) {
            ACCOUNT_LOGE("UpdateCredential failed: accountId %{public}d is invalid.", userId);
            idmCallbackPtr->OnResult(ERR_JS_ACCOUNT_NOT_FOUND, emptyResult);
            return;
        }
        AccountSA::AccountIAMClient::GetInstance().UpdateCredential(userId, innerCredInfo, idmCallbackPtr);
    }

    void DelUser(array_view<uint8_t> token, const IIdmCallback &callback)
    {
        const int32_t defaultUserId = -1;
        std::vector<uint8_t> authTokenVec(token.data(), token.data() + token.size());
        std::shared_ptr<AccountSA::IDMCallback> idmCallbackPtr = std::make_shared<TaiheIDMCallbackAdapter>(callback);

        AccountSA::AccountIAMClient::GetInstance().DelUser(defaultUserId, authTokenVec, idmCallbackPtr);
    }
};

AccountSA::DomainAccountInfo ConvertToDomainAccountInfoInner(const DomainAccountInfo &domainAccountInfo)
{
    AccountSA::DomainAccountInfo domainAccountInfoInner(std::string(domainAccountInfo.domain.c_str()),
                                                        std::string(domainAccountInfo.accountName.c_str()));
    if (domainAccountInfo.accountId.has_value()) {
        domainAccountInfoInner.accountId_ = domainAccountInfo.accountId.value();
    }
    if (domainAccountInfo.serverConfigId.has_value()) {
        domainAccountInfoInner.serverConfigId_ = domainAccountInfo.serverConfigId.value();
    }
    return domainAccountInfoInner;
}

class THDomainAccountCallback : public AccountSA::DomainAccountCallback {
public:
    std::mutex mutex;
    std::condition_variable cv;
    explicit THDomainAccountCallback(IUserAuthCallback callback) : callback_(callback){};

    void OnResult(const int32_t errCode, Parcel &parcel) override
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (this->onResultCalled_) {
            return;
        }
        this->onResultCalled_ = true;
        std::shared_ptr<AccountSA::DomainAuthResult> authResult(AccountSA::DomainAuthResult::Unmarshalling(parcel));
        if (authResult == nullptr) {
            return;
        }
        AuthResult authResultTH;
        if (authResult->authStatusInfo.remainingTimes >= 0) {
            authResultTH.remainTimes = optional<int32_t>(std::in_place_t{}, authResult->authStatusInfo.remainingTimes);
        }
        if (authResult->authStatusInfo.freezingTime >= 0) {
            authResultTH.freezingTime = optional<int32_t>(std::in_place_t{}, authResult->authStatusInfo.freezingTime);
        }
        if (authResult->token.size() > 0) {
            authResultTH.token = optional<array<uint8_t>>(std::in_place_t{}, taihe::copy_data_t{},
                                                          authResult->token.data(), authResult->token.size());
        }
        callback_.onResult(errCode, authResultTH);
    }

private:
    bool onResultCalled_ = false;
    IUserAuthCallback callback_;
};

class DomainPluginImpl {
public:
    DomainPluginImpl() {}

    void Auth(const DomainAccountInfo &domainAccountInfo, array_view<uint8_t> credential,
        const IUserAuthCallback &callback)
    {
        AccountSA::DomainAccountInfo domainAccountInfoInner = ConvertToDomainAccountInfoInner(domainAccountInfo);
        std::vector<uint8_t> authData(credential.data(), credential.data() + credential.size());
        std::shared_ptr<THDomainAccountCallback> domainAuthCallback =
            std::make_shared<THDomainAccountCallback>(callback);
        ErrCode errCode =
            AccountSA::DomainAccountClient::GetInstance().Auth(domainAccountInfoInner, authData, domainAuthCallback);
        if (errCode != ERR_OK) {
            AuthResult emptyResult;
            callback.onResult(ConvertToJSErrCode(errCode), emptyResult);
        }
        return;
    }
};

class DomainAccountManagerImpl {
public:
    DomainAccountManagerImpl() {}
};

void RetrieveStringFromAni(ani_env *env, ani_string str, std::string &res)
{
    ani_size sz {};
    ani_status status = ANI_ERROR;
    if ((status = env->String_GetUTF8Size(str, &sz)) != ANI_OK) {
        ACCOUNT_LOGE("String_GetUTF8Size Fail! status: %{public}d", status);
        return;
    }
    res.resize(sz + 1);
    if ((status = env->String_GetUTF8SubString(str, 0, sz, res.data(), res.size(), &sz)) != ANI_OK) {
        ACCOUNT_LOGE("String_GetUTF8SubString Fail! status: %{public}d", status);
        return;
    }
    res.resize(sz);
}

std::string ConvertMapViewToStringInner(uintptr_t parameters)
{
    ani_env *env = get_env();
    ani_class cls;
    ani_status status = env->FindClass("Lescompat/JSON;", &cls);
    ani_static_method stringify;
    if (status != ANI_OK) {
        ACCOUNT_LOGE("JSON not found, ret: %{public}d.", status);
        return "";
    }
    status = env->Class_FindStaticMethod(cls, "stringify", "Lstd/core/Object;:Lstd/core/String;", &stringify);
    if (status != ANI_OK) {
        ACCOUNT_LOGE("Stringify not found, ret: %{public}d.", status);
        return "";
    }
    ani_ref result;
    status = env->Class_CallStaticMethod_Ref(cls, stringify, &result, reinterpret_cast<ani_object>(parameters));
    if (status != ANI_OK) {
        ACCOUNT_LOGE("JSON.stringify run failed, ret: %{public}d.", status);
        return "";
    }
    std::string parametersInnerString;
    RetrieveStringFromAni(env, reinterpret_cast<ani_string>(result), parametersInnerString);
    return parametersInnerString;
}

DomainServerConfig ConvertToDomainServerConfigTH(std::string id, std::string domain, std::string parameters)
{
    const DomainServerConfig emptyDomainServerConfig = {
        .parameters = 0,
        .id = string(""),
        .domain = string("")
    };
    if (parameters.empty()) {
        ACCOUNT_LOGE("Parameters is invalid.");
        return emptyDomainServerConfig;
    }
    auto parametersJson = nlohmann::json::parse(parameters, nullptr, false);
    if (parametersJson.is_discarded()) {
        ACCOUNT_LOGE("Failed to parse json string");
        return emptyDomainServerConfig;
    }
    ani_env *env = get_env();
    AAFwk::WantParams parametersWantParams;
    from_json(parametersJson, parametersWantParams);
    auto parametersRef = AppExecFwk::WrapWantParams(env, parametersWantParams);
    DomainServerConfig domainServerConfig = DomainServerConfig{
        .id = id,
        .domain = domain,
        .parameters = reinterpret_cast<uintptr_t>(parametersRef),
    };
    return domainServerConfig;
}

class OnSetDataCallbackImpl {
private:
    std::shared_ptr<AccountSA::IInputerData> inputerData_;
public:
    explicit OnSetDataCallbackImpl(std::shared_ptr<AccountSA::IInputerData> inputerData) : inputerData_(inputerData) {}
    void operator()(AuthSubType authSubType, ::taihe::array_view<uint8_t> data) __attribute__((no_sanitize("cfi")))
    {
        bool isSystemApp = OHOS::AccountSA::IsSystemApp();
        if (!isSystemApp) {
            ACCOUNT_LOGE("Not system app.");
            taihe::set_business_error(ERR_JS_IS_NOT_SYSTEM_APP, ConvertToJsErrMsg(ERR_JS_IS_NOT_SYSTEM_APP));
            return;
        }
        std::vector<uint8_t> authTokenVec(data.data(), data.data() + data.size());
        inputerData_->OnSetData(static_cast<int32_t>(authSubType), authTokenVec);
        inputerData_ = nullptr;
    }
};

class DomainServerConfigManagerImpl {
private:
    AccountSA::OsAccountManager *osAccountManger_ = nullptr;

public:
    DomainServerConfigManagerImpl()
    {
        osAccountManger_ = new (std::nothrow) AccountSA::OsAccountManager();
    }

    ~DomainServerConfigManagerImpl()
    {
        if (osAccountManger_ != nullptr) {
            delete osAccountManger_;
            osAccountManger_ = nullptr;
        }
    }
};

class IInputDataImpl {
public:
    std::shared_ptr<AccountSA::IInputerData> inputerData_;

public:
    IInputDataImpl() {}

    explicit IInputDataImpl(int64_t ptr)
    {
        AccountSA::IInputerData* rawPtr = reinterpret_cast<AccountSA::IInputerData*>(ptr);
        inputerData_ = std::shared_ptr<AccountSA::IInputerData>(
            rawPtr,
            [](AccountSA::IInputerData *p) {
                if (p != nullptr) {
                    delete p;
                }
            }
        );
    }

    int64_t GetSpecificImplPtr()
    {
        return reinterpret_cast<int64_t>(this);
    }

    int64_t GetIInputDataPtr()
    {
        return reinterpret_cast<int64_t>(inputerData_.get());
    }

    void OnSetData(AuthSubType authSubType, array_view<uint8_t> data) __attribute__((no_sanitize("cfi")))
    {
        bool isSystemApp = OHOS::AccountSA::IsSystemApp();
        if (!isSystemApp) {
            ACCOUNT_LOGE("Not system app.");
            taihe::set_business_error(ERR_JS_IS_NOT_SYSTEM_APP, ConvertToJsErrMsg(ERR_JS_IS_NOT_SYSTEM_APP));
            return;
        }
        std::vector<uint8_t> authTokenVec(data.data(), data.data() + data.size());
        if (inputerData_ == nullptr) {
            ACCOUNT_LOGE("InputerData_ is nullptr.");
            taihe::set_business_error(ERR_JS_SYSTEM_SERVICE_EXCEPTION,
                ConvertToJsErrMsg(ERR_JS_SYSTEM_SERVICE_EXCEPTION));
            return;
        }
        inputerData_->OnSetData(static_cast<int32_t>(authSubType), authTokenVec);
        inputerData_ = nullptr;
    }

    ::taihe::callback<void(AuthSubType authSubType, ::taihe::array_view<uint8_t> data)> GetOnSetData()
    {
        ::taihe::callback<void(AuthSubType authSubType, ::taihe::array_view<uint8_t> data)> cb =
            ::taihe::make_holder<OnSetDataCallbackImpl,
            ::taihe::callback<void(AuthSubType authSubType, ::taihe::array_view<uint8_t> data)>>(inputerData_);
        return cb;
    }
};

IInputData createIInputData(int64_t ptr)
{
    return make_holder<IInputDataImpl, IInputData>(ptr);
}

int64_t getPtrByIInputData(IInputData data)
{
    return data->GetIInputDataPtr();
}

AccountSA::RemoteAuthOptions ConvertToRemoteAuthOptionsInner(const RemoteAuthOptions &options)
{
    AccountSA::RemoteAuthOptions remoteAuthOptionsInner;
    if (options.verifierNetworkId.has_value()) {
        remoteAuthOptionsInner.hasVerifierNetworkId = true;
        remoteAuthOptionsInner.verifierNetworkId = std::string(options.verifierNetworkId.value().c_str());
    }
    if (options.collectorNetworkId.has_value()) {
        remoteAuthOptionsInner.hasCollectorNetworkId = true;
        remoteAuthOptionsInner.collectorNetworkId = std::string(options.collectorNetworkId.value().c_str());
    }
    if (options.collectorTokenId.has_value()) {
        remoteAuthOptionsInner.hasCollectorTokenId = true;
        remoteAuthOptionsInner.collectorTokenId = options.collectorTokenId.value();
    }
    return remoteAuthOptionsInner;
}

AccountSA::AuthOptions ConvertToAuthOptionsInner(const AuthOptions &options)
{
    AccountSA::AuthOptions authOptionsInner;
    if (options.accountId.has_value()) {
        authOptionsInner.hasAccountId = true;
        authOptionsInner.accountId = options.accountId.value();
    }
    if (options.authIntent.has_value()) {
        authOptionsInner.authIntent = static_cast<AccountSA::AuthIntent>(options.authIntent.value().get_value());
    }
    if (options.remoteAuthOptions.has_value()) {
        authOptionsInner.hasRemoteAuthOptions = true;
        authOptionsInner.remoteAuthOptions = ConvertToRemoteAuthOptionsInner(options.remoteAuthOptions.value());
    }
    return authOptionsInner;
}

bool ConvertGetPropertyTypeToAttributeKeyTh(AccountJsKit::GetPropertyType in, AccountSA::Attributes::AttributeKey &out)
{
    static const std::map<AccountJsKit::GetPropertyType, AccountSA::Attributes::AttributeKey> type2Key = {
        {AccountJsKit::GetPropertyType::AUTH_SUB_TYPE, AccountSA::Attributes::AttributeKey::ATTR_PIN_SUB_TYPE},
        {AccountJsKit::GetPropertyType::REMAIN_TIMES, AccountSA::Attributes::AttributeKey::ATTR_REMAIN_TIMES},
        {AccountJsKit::GetPropertyType::FREEZING_TIME, AccountSA::Attributes::AttributeKey::ATTR_FREEZING_TIME},
        {AccountJsKit::GetPropertyType::ENROLLMENT_PROGRESS, AccountSA::Attributes::AttributeKey::ATTR_ENROLL_PROGRESS},
        {AccountJsKit::GetPropertyType::SENSOR_INFO, AccountSA::Attributes::AttributeKey::ATTR_SENSOR_INFO},
        {AccountJsKit::GetPropertyType::NEXT_PHASE_FREEZING_TIME,
         AccountSA::Attributes::AttributeKey::ATTR_NEXT_FAIL_LOCKOUT_DURATION},
    };

    auto iter = type2Key.find(in);
    if (iter == type2Key.end()) {
        return false;
    } else {
        out = iter->second;
    }
    return true;
}

bool ConvertToGetPropertyRequestInner(const GetPropertyRequest &request,
    AccountSA::GetPropertyRequest &getPropertyRequestInner)
{
    getPropertyRequestInner.authType = static_cast<AccountSA::AuthType>(request.authType.get_value());

    for (GetPropertyType each : request.keys) {
        AccountSA::Attributes::AttributeKey key;
        if (!ConvertGetPropertyTypeToAttributeKeyTh(static_cast<AccountJsKit::GetPropertyType>(each.get_value()),
                                                    key)) {
            return false;
        }
        getPropertyRequestInner.keys.emplace_back(key);
    }
    return true;
}

bool ConvertToSetPropertyRequestInner(const SetPropertyRequest &request,
    AccountSA::SetPropertyRequest &setPropertyRequestInner)
{
    setPropertyRequestInner.authType = static_cast<AccountSA::AuthType>(request.authType.get_value());
    setPropertyRequestInner.mode = static_cast<AccountSA::PropertyMode>(request.key.get_value());

    const auto &taiheSetInfo = request.setInfo;
    std::vector<uint8_t> valueVec(taiheSetInfo.data(), taiheSetInfo.data() + taiheSetInfo.size());
    setPropertyRequestInner.attrs.SetUint8ArrayValue(AccountSA::Attributes::AttributeKey(setPropertyRequestInner.mode),
                                                     valueVec);
    return true;
}

ExecutorProperty CreateEmptyExecutorPropertyTH()
{
    return ExecutorProperty{
        .result = 0,
        .authSubType = AuthSubType(AuthSubType::key_t::INVALID),
        .remainTimes = optional<int32_t>(std::nullopt),
        .freezingTime = optional<int32_t>(std::nullopt),
        .enrollmentProgress = optional<string>(std::nullopt),
        .sensorInfo = optional<string>(std::nullopt),
        .nextPhaseFreezingTime = optional<int32_t>(std::nullopt),
    };
}

ExecutorProperty ConvertToExecutorPropertyTH(
    const AccountJsKit::ExecutorProperty &propertyInfoInner,
    const std::vector<AccountSA::Attributes::AttributeKey> &keys)
{
    ExecutorProperty propertyTH = CreateEmptyExecutorPropertyTH();
    for (const auto &key : keys) {
        switch (key) {
            case AccountSA::Attributes::AttributeKey::ATTR_PIN_SUB_TYPE:
                propertyTH.authSubType =
                    ConvertToAuthSubTypeTH(static_cast<AccountSA::PinSubType>(propertyInfoInner.authSubType));
                break;
            case AccountSA::Attributes::AttributeKey::ATTR_REMAIN_TIMES:
                if (propertyInfoInner.remainTimes.has_value()) {
                    propertyTH.remainTimes = optional<int32_t>(
                        std::in_place_t{}, propertyInfoInner.remainTimes.value());
                }
                break;
            case AccountSA::Attributes::AttributeKey::ATTR_FREEZING_TIME:
                if (propertyInfoInner.freezingTime.has_value()) {
                    propertyTH.freezingTime = optional<int32_t>(
                        std::in_place_t{}, propertyInfoInner.freezingTime.value());
                }
                break;
            case AccountSA::Attributes::AttributeKey::ATTR_ENROLL_PROGRESS:
                if (propertyInfoInner.enrollmentProgress.has_value()) {
                    propertyTH.enrollmentProgress =
                        optional<string>(std::in_place_t{}, propertyInfoInner.enrollmentProgress.value());
                }
                break;
            case AccountSA::Attributes::AttributeKey::ATTR_SENSOR_INFO:
                if (propertyInfoInner.sensorInfo.has_value()) {
                    propertyTH.sensorInfo = optional<string>(
                        std::in_place_t{}, propertyInfoInner.sensorInfo.value());
                }
                break;
            case AccountSA::Attributes::AttributeKey::ATTR_NEXT_FAIL_LOCKOUT_DURATION:
                if (propertyInfoInner.nextPhaseFreezingTime.has_value()) {
                    propertyTH.nextPhaseFreezingTime =
                        optional<int32_t>(std::in_place_t{}, propertyInfoInner.nextPhaseFreezingTime.value());
                }
                break;
            default:
                break;
        }
    }
    return propertyTH;
}

AuthResult CreateEmptyAuthResultTH()
{
    AuthResult authResultTH{
        .token = optional<array<uint8_t>>(std::nullopt),
        .remainTimes = optional<int32_t>(std::nullopt),
        .freezingTime = optional<int32_t>(std::nullopt),
        .nextPhaseFreezingTime = optional<int32_t>(std::nullopt),
        .credentialId = optional<array<uint8_t>>(std::nullopt),
        .accountId = optional<int32_t>(std::nullopt),
        .pinValidityPeriod = optional<int64_t>(std::nullopt),
    };
    return authResultTH;
}

struct AuthCallbackParam {
    int32_t remainTimes = -1;
    int32_t freezingTime = -1;
    std::vector<uint8_t> token;
    bool hasNextPhaseFreezingTime = false;
    bool hasCredentialId = false;
    bool hasAccountId = false;
    bool hasPinValidityPeriod = false;
    int32_t nextPhaseFreezingTime = -1;
    uint64_t credentialId = 0;
    int32_t accountId = -1;
    int64_t pinValidityPeriod = -1;
};

AuthResult ConvertToAuthResultTH(const AccountSA::Attributes &extraInfo)
{
    AuthCallbackParam param;
    extraInfo.GetUint8ArrayValue(AccountSA::Attributes::AttributeKey::ATTR_SIGNATURE, param.token);
    extraInfo.GetInt32Value(AccountSA::Attributes::AttributeKey::ATTR_REMAIN_TIMES, param.remainTimes);
    extraInfo.GetInt32Value(AccountSA::Attributes::AttributeKey::ATTR_FREEZING_TIME, param.freezingTime);
    if (extraInfo.GetInt32Value(AccountSA::Attributes::AttributeKey::ATTR_NEXT_FAIL_LOCKOUT_DURATION,
                                param.nextPhaseFreezingTime)) {
        param.hasNextPhaseFreezingTime = true;
    }
    if (extraInfo.GetUint64Value(AccountSA::Attributes::AttributeKey::ATTR_CREDENTIAL_ID, param.credentialId)) {
        param.hasCredentialId = true;
    }
    if (extraInfo.GetInt32Value(AccountSA::Attributes::AttributeKey::ATTR_USER_ID, param.accountId)) {
        param.hasAccountId = true;
    }
    if (extraInfo.GetInt64Value(AccountSA::Attributes::AttributeKey::ATTR_PIN_EXPIRED_INFO, param.pinValidityPeriod)) {
        param.hasPinValidityPeriod = true;
    }
    AuthResult authResultTH = CreateEmptyAuthResultTH();
    if (param.remainTimes >= 0) {
        authResultTH.remainTimes = optional<int32_t>(std::in_place_t{}, param.remainTimes);
    }
    if (param.freezingTime >= 0) {
        authResultTH.freezingTime = optional<int32_t>(std::in_place_t{}, param.freezingTime);
    }
    if (param.token.size() > 0) {
        authResultTH.token =
            optional<array<uint8_t>>(std::in_place_t{}, taihe::copy_data_t{}, param.token.data(), param.token.size());
    }
    if (param.hasNextPhaseFreezingTime) {
        authResultTH.nextPhaseFreezingTime = optional<int32_t>(std::in_place_t{}, param.nextPhaseFreezingTime);
    }
    if (param.hasCredentialId) {
        authResultTH.credentialId =
            optional<array<uint8_t>>(std::in_place_t{}, taihe::copy_data_t{},
                reinterpret_cast<uint8_t *>(&param.credentialId), sizeof(uint64_t));
    }
    if (param.hasAccountId) {
        authResultTH.accountId = optional<int32_t>(std::in_place_t{}, param.accountId);
    }
    if (param.hasPinValidityPeriod) {
        authResultTH.pinValidityPeriod = optional<int64_t>(std::in_place_t{}, param.pinValidityPeriod);
    }
    return authResultTH;
}

class THUserAuthCallback : public AccountSA::IDMCallback {
public:
    explicit THUserAuthCallback(const IUserAuthCallback &callback) : callback_(callback){};

    void OnResult(int32_t result, const AccountSA::Attributes &extraInfo) override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (onResultCalled_) {
            return;
        }
        onResultCalled_ = true;

        callback_.onResult(AccountIAMConvertToJSErrCode(result), ConvertToAuthResultTH(extraInfo));
    };

    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const AccountSA::Attributes &extraInfo) override
    {
        if (!callback_.onAcquireInfo.has_value()) {
            return;
        }
        std::vector<uint8_t> infoArray;
        extraInfo.GetUint8ArrayValue(AccountSA::Attributes::AttributeKey::ATTR_EXTRA_INFO, infoArray);
        taihe::array<uint8_t> thInfoArray(taihe::copy_data_t{}, infoArray.data(), infoArray.size());
        callback_.onAcquireInfo.value()(module, static_cast<int32_t>(acquireInfo), thInfoArray);
    };

private:
    const IUserAuthCallback callback_;
    std::mutex mutex_;
    bool onResultCalled_ = false;
};

class THGetPropCallback : public AccountSA::GetSetPropCallback {
public:
    std::mutex mutex;
    std::condition_variable cv;
    bool isGetById = false;
    int32_t errCode = 0;
    AccountJsKit::ExecutorProperty propertyInfoInner;
    std::vector<UserIam::UserAuth::Attributes::AttributeKey> keys{};

    explicit THGetPropCallback(std::vector<UserIam::UserAuth::Attributes::AttributeKey> keys) : keys(keys){};

private:
    void ProcessRemainTimes(const UserIam::UserAuth::Attributes &extraInfo,
                           AccountJsKit::ExecutorProperty &propertyInfo)
    {
        int32_t tempValue;
        if (extraInfo.GetInt32Value(
            AccountSA::Attributes::AttributeKey::ATTR_REMAIN_TIMES, tempValue)) {
            propertyInfo.remainTimes = tempValue;
        }
    }

    void ProcessFreezingTime(const UserIam::UserAuth::Attributes &extraInfo,
                            AccountJsKit::ExecutorProperty &propertyInfo)
    {
        int32_t tempValue;
        if (extraInfo.GetInt32Value(
            AccountSA::Attributes::AttributeKey::ATTR_FREEZING_TIME, tempValue)) {
            propertyInfo.freezingTime = tempValue;
        }
    }

    void ProcessEnrollProgress(const UserIam::UserAuth::Attributes &extraInfo,
                              AccountJsKit::ExecutorProperty &propertyInfo)
    {
        std::string tempValue;
        if (extraInfo.GetStringValue(
            AccountSA::Attributes::AttributeKey::ATTR_ENROLL_PROGRESS, tempValue)) {
            propertyInfo.enrollmentProgress = tempValue;
        }
    }

    void ProcessSensorInfo(const UserIam::UserAuth::Attributes &extraInfo,
                          AccountJsKit::ExecutorProperty &propertyInfo)
    {
        std::string tempValue;
        if (extraInfo.GetStringValue(
            AccountSA::Attributes::AttributeKey::ATTR_SENSOR_INFO, tempValue)) {
            propertyInfo.sensorInfo = tempValue;
        }
    }

    void ProcessNextPhaseFreezingTime(const UserIam::UserAuth::Attributes &extraInfo,
                                     AccountJsKit::ExecutorProperty &propertyInfo)
    {
        int32_t tempValue;
        if (extraInfo.GetInt32Value(
            AccountSA::Attributes::AttributeKey::ATTR_NEXT_FAIL_LOCKOUT_DURATION, tempValue)) {
            propertyInfo.nextPhaseFreezingTime = tempValue;
        }
    }

public:
    void GetExecutorPropertys(const UserIam::UserAuth::Attributes &extraInfo,
                             AccountJsKit::ExecutorProperty &propertyInfo)
    {
        for (const auto &key : keys) {
            switch (key) {
                case AccountSA::Attributes::AttributeKey::ATTR_PIN_SUB_TYPE:
                    extraInfo.GetInt32Value(AccountSA::Attributes::AttributeKey::ATTR_PIN_SUB_TYPE,
                        propertyInfo.authSubType);
                    break;
                case AccountSA::Attributes::AttributeKey::ATTR_REMAIN_TIMES:
                    ProcessRemainTimes(extraInfo, propertyInfo);
                    break;
                case AccountSA::Attributes::AttributeKey::ATTR_FREEZING_TIME:
                    ProcessFreezingTime(extraInfo, propertyInfo);
                    break;
                case AccountSA::Attributes::AttributeKey::ATTR_ENROLL_PROGRESS:
                    ProcessEnrollProgress(extraInfo, propertyInfo);
                    break;
                case AccountSA::Attributes::AttributeKey::ATTR_SENSOR_INFO:
                    ProcessSensorInfo(extraInfo, propertyInfo);
                    break;
                case AccountSA::Attributes::AttributeKey::ATTR_NEXT_FAIL_LOCKOUT_DURATION:
                    ProcessNextPhaseFreezingTime(extraInfo, propertyInfo);
                    break;
                default:
                    break;
            }
        }
    }

    void OnResult(int32_t result, const AccountSA::Attributes &extraInfo) override
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (onResultCalled) {
            return;
        }
        onResultCalled = true;
        GetExecutorPropertys(extraInfo, propertyInfoInner);
        propertyInfoInner.result = result;
        if (!isGetById && (result == IAMResultCode::ERR_IAM_NOT_ENROLLED)) {
            result = ERR_OK;
        }
        if (result != ERR_OK) {
            int32_t jsErrCode = AccountIAMConvertToJSErrCode(propertyInfoInner.result);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
            return;
        }
        errCode = ERR_OK;
        cv.notify_one();
    }

    bool onResultCalled = false;
};

class THSetPropCallback : public AccountSA::GetSetPropCallback {
public:
    std::mutex mutex;
    std::condition_variable cv;
    bool onResultCalled = false;
    int32_t errCode = 0;

    void OnResult(int32_t result, const AccountSA::Attributes &extraInfo) override
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (onResultCalled) {
            ACCOUNT_LOGE("OnResult called more than once.");
            return;
        }
        onResultCalled = true;
        errCode = result;
        cv.notify_one();
    }
};

class UserAuthImpl {
public:
    UserAuthImpl() {}

    array<uint8_t> AuthSync(array_view<uint8_t> challenge, AuthType authType, AuthTrustLevel authTrustLevel,
                            const IUserAuthCallback &callback)
    {
        int32_t authTypeInner = authType.get_value();
        int32_t trustLevelInner = authTrustLevel.get_value();
        std::shared_ptr<THUserAuthCallback> callbackInner = std::make_shared<THUserAuthCallback>(callback);
        std::vector<uint8_t> challengeInner(challenge.begin(), challenge.begin() + challenge.size());
        AccountSA::AuthOptions authOptionsInner;
        uint64_t contextId = AccountSA::AccountIAMClient::GetInstance().Auth(
            authOptionsInner, challengeInner, static_cast<AccountSA::AuthType>(authTypeInner),
            static_cast<AccountSA::AuthTrustLevel>(trustLevelInner), callbackInner);
        return taihe::array<uint8_t>(taihe::copy_data_t{}, reinterpret_cast<uint8_t *>(&contextId), sizeof(uint64_t));
    }

    array<uint8_t> AuthWithOptSync(array_view<uint8_t> challenge, AuthType authType, AuthTrustLevel authTrustLevel,
                                   const AuthOptions &options, const IUserAuthCallback &callback)
    {
        int32_t authTypeInner = authType.get_value();
        int32_t trustLevelInner = authTrustLevel.get_value();
        std::shared_ptr<THUserAuthCallback> callbackInner = std::make_shared<THUserAuthCallback>(callback);
        std::vector<uint8_t> challengeInner(challenge.begin(), challenge.begin() + challenge.size());
        AccountSA::AuthOptions authOptionsInner = ConvertToAuthOptionsInner(options);
        if ((!authOptionsInner.hasRemoteAuthOptions) && (authOptionsInner.hasAccountId) &&
            (!AccountSA::IsAccountIdValid(authOptionsInner.accountId))) {
            AccountSA::Attributes emptyInfo;
            callbackInner->OnResult(ERR_JS_ACCOUNT_NOT_FOUND, emptyInfo);
            return taihe::array<uint8_t>::make(0);
        }
        uint64_t contextId = AccountSA::AccountIAMClient::GetInstance().Auth(
            authOptionsInner, challengeInner, static_cast<AccountSA::AuthType>(authTypeInner),
            static_cast<AccountSA::AuthTrustLevel>(trustLevelInner), callbackInner);
        return taihe::array<uint8_t>(taihe::copy_data_t{}, reinterpret_cast<uint8_t *>(&contextId), sizeof(uint64_t));
    }

    array<uint8_t> AuthUser(int32_t userId, array_view<uint8_t> challenge, AuthType authType,
                            AuthTrustLevel authTrustLevel, const IUserAuthCallback &callback)
    {
        int32_t authTypeInner = authType.get_value();
        int32_t trustLevelInner = authTrustLevel.get_value();
        std::shared_ptr<THUserAuthCallback> callbackInner = std::make_shared<THUserAuthCallback>(callback);
        std::vector<uint8_t> challengeInner(challenge.begin(), challenge.begin() + challenge.size());
        AccountSA::AuthOptions authOptionsInner;

        if (!AccountSA::IsAccountIdValid(userId)) {
            AccountSA::Attributes emptyInfo;
            callbackInner->OnResult(ERR_JS_ACCOUNT_NOT_FOUND, emptyInfo);
            return taihe::array<uint8_t>::make(0);
        }
        authOptionsInner.accountId = userId;
        uint64_t contextId = AccountSA::AccountIAMClient::GetInstance().AuthUser(
            authOptionsInner, challengeInner, static_cast<AccountSA::AuthType>(authTypeInner),
            static_cast<AccountSA::AuthTrustLevel>(trustLevelInner), callbackInner);
        return taihe::array<uint8_t>(taihe::copy_data_t{}, reinterpret_cast<uint8_t *>(&contextId), sizeof(uint64_t));
    }

    void CancelAuth(array_view<uint8_t> contextID)
    {
        uint64_t contextId = 0;
        if (contextID.size() != sizeof(uint64_t)) {
            ACCOUNT_LOGE("contextID size is invalid.");
            std::string errMsg = "Parameter error. The type of \"contextID\" must be Uint8Array";
            taihe::set_business_error(ERR_JS_PARAMETER_ERROR, errMsg);
            return;
        }
        for (auto each : contextID) {
            contextId = (contextId << CONTEXTID_OFFSET);
            contextId += each;
        }
        ErrCode errCode = AccountSA::AccountIAMClient::GetInstance().CancelAuth(contextId);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("CancelAuth failed, ret = %{public}d", errCode);
            errCode = AccountIAMConvertToJSErrCode(errCode);
            taihe::set_business_error(errCode, ConvertToJsErrMsg(errCode));
        }
        return;
    }

    ExecutorProperty GetPropertySync(const GetPropertyRequest &request)
    {
        AccountSA::GetPropertyRequest getPropertyRequestInner;
        if (!ConvertToGetPropertyRequestInner(request, getPropertyRequestInner)) {
            int32_t jsErrCode = AccountIAMConvertToJSErrCode(ERR_JS_PARAMETER_ERROR);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
            return CreateEmptyExecutorPropertyTH();
        }

        std::shared_ptr<THGetPropCallback> idmCallback =
            std::make_shared<THGetPropCallback>(getPropertyRequestInner.keys);
        if (request.accountId.has_value() && !AccountSA::IsAccountIdValid(request.accountId.value())) {
            idmCallback->OnResult(ERR_JS_ACCOUNT_NOT_FOUND, AccountSA::Attributes());
            return ConvertToExecutorPropertyTH(idmCallback->propertyInfoInner, idmCallback->keys);
        }
        AccountSA::AccountIAMClient::GetInstance().GetProperty(request.accountId.value_or(-1), getPropertyRequestInner,
                                                               idmCallback);
        std::unique_lock<std::mutex> lock(idmCallback->mutex);
        idmCallback->cv.wait(lock, [idmCallback] { return idmCallback->onResultCalled; });
        return ConvertToExecutorPropertyTH(idmCallback->propertyInfoInner, idmCallback->keys);
    }

    void SetPropertySync(const SetPropertyRequest &request)
    {
        AccountSA::SetPropertyRequest setPropertyRequestInner;
        if (!ConvertToSetPropertyRequestInner(request, setPropertyRequestInner)) {
            int32_t jsErrCode = AccountIAMConvertToJSErrCode(ERR_JS_PARAMETER_ERROR);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
            return;
        }

        std::shared_ptr<THSetPropCallback> callback = std::make_shared<THSetPropCallback>();
        int32_t accountId = -1;
        AccountSA::AccountIAMClient::GetInstance().SetProperty(accountId, setPropertyRequestInner, callback);

        std::unique_lock<std::mutex> lock(callback->mutex);
        callback->cv.wait(lock, [callback] { return callback->onResultCalled; });

        if (callback->errCode != ERR_OK) {
            int32_t jsErrCode = AccountIAMConvertToJSErrCode(callback->errCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
    }
};

class TaiheGetDataCallback : public AccountSA::IInputer {
public:
    TaiheGetDataCallback();
    ~TaiheGetDataCallback();

    void OnGetData(int32_t authSubType, std::vector<uint8_t> challenge,
                   const std::shared_ptr<AccountSA::IInputerData> inputerData) override;

    std::shared_ptr<TaiheIInputer> inputer_ = nullptr;
    std::shared_ptr<TaiheIInputData> inputerData_ = nullptr;
};

TaiheGetDataCallback::TaiheGetDataCallback() {}

TaiheGetDataCallback::~TaiheGetDataCallback() {}

void TaiheGetDataCallback::OnGetData(int32_t authSubType, std::vector<uint8_t> challenge,
                                     const std::shared_ptr<AccountSA::IInputerData> inputerData)
{
    ACCOUNT_LOGI("Start!");
    if (inputer_ == nullptr) {
        ACCOUNT_LOGE("The onGetData function is undefined");
        return;
    }
    GetInputDataOptions option = {
        optional<array<uint8_t>>(std::in_place_t{}, taihe::copy_data_t{}, challenge.data(), challenge.size())};
    reinterpret_cast<IInputDataImpl *>((*inputerData_)->GetSpecificImplPtr())->inputerData_ = inputerData;
    inputer_->onGetData(AuthSubType::from_value(authSubType), *inputerData_, option);
}

class PINAuthImpl {
public:
    PINAuthImpl() {}

    void RegisterInputer(const IInputer &inputer)
    {
        auto taiheInputer = std::make_shared<TaiheIInputer>(inputer);
        auto taiheCallbackRef = std::make_shared<TaiheGetDataCallback>();
        taiheCallbackRef->inputer_ = taiheInputer;
        taiheCallbackRef->inputerData_ = std::make_shared<IInputData>(make_holder<IInputDataImpl, IInputData>());
        ErrCode errCode = AccountSA::AccountIAMClient::GetInstance().RegisterPINInputer(taiheCallbackRef);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("Failed to register inputer, errCode=%{public}d", errCode);
            int32_t jsErrCode = AccountIAMConvertToJSErrCode(errCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
    }

    void UnregisterInputer()
    {
        ErrCode errCode = AccountSA::AccountIAMClient::GetInstance().UnregisterPINInputer();
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("Failed to unregister PIN inputer, errCode=%{public}d", errCode);
            int32_t jsErrCode = AccountIAMConvertToJSErrCode(errCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
    }
};

DomainAccountInfo ConvertToDomainAccountInfo(const AccountSA::DomainAccountInfo &domainAccountInfo)
{
    return DomainAccountInfo{
        .domain = taihe::string(domainAccountInfo.domain_.c_str()),
        .accountName = taihe::string(domainAccountInfo.accountName_.c_str()),
        .accountId = optional<string>(std::in_place_t{}, domainAccountInfo.accountId_),
        .isAuthenticated = optional<bool>(std::in_place_t{}, domainAccountInfo.isAuthenticated),
        .serverConfigId = optional<string>(std::in_place_t{}, domainAccountInfo.serverConfigId_),
    };
}

class OnResultCallbackImpl {
public:
    explicit OnResultCallbackImpl(std::shared_ptr<AccountSA::DomainAccountCallback> callback)
        : callback_(callback) {}

    void operator()(int32_t result, const ::ohos::account::osAccount::AuthResult& extraInfo) {
        if (callback_ == nullptr) {
            ACCOUNT_LOGE("native callback is nullptr");
            return;
        }

        AccountSA::DomainAuthResult nativeResult;

        if (extraInfo.token.has_value()) {
            const auto& taiheToken = extraInfo.token.value();
            nativeResult.token.assign(taiheToken.data(), taiheToken.data() + taiheToken.size());
        } else {
            nativeResult.token.clear();
        }

        nativeResult.authStatusInfo.remainingTimes = extraInfo.remainTimes.has_value() ?
            extraInfo.remainTimes.value() : -1;
        nativeResult.authStatusInfo.freezingTime = extraInfo.freezingTime.has_value() ?
            extraInfo.freezingTime.value() : -1;

        Parcel parcel;
        if (!nativeResult.Marshalling(parcel)) {
            Parcel emptyParcel;
            callback_->OnResult(ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR, emptyParcel);
            return;
        }
        callback_->OnResult(result, parcel);
        ACCOUNT_LOGI("Successfully called native callback");
    }

private:
    std::shared_ptr<AccountSA::DomainAccountCallback> callback_;
};

class TaiheDomainPluginBridge : public AccountSA::DomainAccountPlugin {
public:
    explicit TaiheDomainPluginBridge(const DomainPlugin& jsPlugin)
        : jsPlugin_(jsPlugin) {}

    void Auth(const AccountSA::DomainAccountInfo &info, const std::vector<uint8_t> &credential,
        const std::shared_ptr<AccountSA::DomainAccountCallback> &callback) override
    {
        DomainAccountInfo taiheInfo = ConvertToDomainAccountInfo(info);
        taihe::array<uint8_t> taiheCredential(taihe::copy_data_t{}, credential.data(), credential.size());
        IUserAuthCallback taiheCallback = ConvertToDomainAccountCallback(callback);
        jsPlugin_.Auth(taiheInfo, taiheCredential, taiheCallback);
    }

    void AuthWithPopup(const AccountSA::DomainAccountInfo &info,
        const std::shared_ptr<AccountSA::DomainAccountCallback> &callback)
    {
        DomainAccountInfo taiheInfo = ConvertToDomainAccountInfo(info);
        IUserAuthCallback taiheCallback = ConvertToDomainAccountCallback(callback);
        jsPlugin_.AuthWithPopup(taiheInfo, taiheCallback);
    }

    void AuthWithToken(const AccountSA::DomainAccountInfo &info, const std::vector<uint8_t> &token,
        const std::shared_ptr<AccountSA::DomainAccountCallback> &callback)
    {
        DomainAccountInfo taiheInfo = ConvertToDomainAccountInfo(info);
        taihe::array<uint8_t> taiheToken(taihe::copy_data_t{}, token.data(), token.size());
        IUserAuthCallback taiheCallback = ConvertToDomainAccountCallback(callback);
        jsPlugin_.AuthWithToken(taiheInfo, taiheToken, taiheCallback);
    }

    void GetDomainAccountInfo(const AccountSA::GetDomainAccountInfoOptions &options,
        const std::shared_ptr<AccountSA::DomainAccountCallback> &callback)
    {
        GetDomainAccountInfoOptions option{
            .accountName = options.accountInfo.accountName_.c_str(),
            .domain = optional<string>(std::in_place_t{}, options.accountInfo.domain_),
            .serverConfigId = optional<string>(std::in_place_t{}, options.accountInfo.serverConfigId_),
        };
        GetDomainAccountInfoPluginOptions taiheOptions{
            .options = option,
            .callerUid = options.callingUid,
        };
        jsPlugin_.GetAccountInfoSync(taiheOptions);
    }

    void GetAuthStatusInfo(const AccountSA::DomainAccountInfo &info,
        const std::shared_ptr<AccountSA::DomainAccountCallback> &callback)
    {
        DomainAccountInfo taiheInfo = ConvertToDomainAccountInfo(info);
        jsPlugin_.GetAuthStatusInfoSync(taiheInfo);
    }

    void OnAccountBound(const AccountSA::DomainAccountInfo &info, const int32_t localId,
        const std::shared_ptr<AccountSA::DomainAccountCallback> &callback)
    {
        DomainAccountInfo taiheInfo = ConvertToDomainAccountInfo(info);
        jsPlugin_.BindAccountSync(taiheInfo, localId);
    }

    void OnAccountUnBound(const AccountSA::DomainAccountInfo &info,
        const std::shared_ptr<AccountSA::DomainAccountCallback> &callback)
    {
        DomainAccountInfo taiheInfo = ConvertToDomainAccountInfo(info);
        jsPlugin_.UnbindAccountSync(taiheInfo);
    }

    void IsAccountTokenValid(const AccountSA::DomainAccountInfo &info, const std::vector<uint8_t> &token,
        const std::shared_ptr<AccountSA::DomainAccountCallback> &callback)
    {
        DomainAccountInfo taiheInfo = ConvertToDomainAccountInfo(info);
        taihe::array<uint8_t> taiheToken(taihe::copy_data_t{}, token.data(), token.size());
        jsPlugin_.IsAccountTokenValidSync(taiheInfo, taiheToken);
    }

    void GetAccessToken(const AccountSA::DomainAccountInfo &domainInfo, const std::vector<uint8_t> &accountToken,
        const AccountSA::GetAccessTokenOptions &option,
        const std::shared_ptr<AccountSA::DomainAccountCallback> &callback)
    {
        taihe::array<uint8_t> taiheToken(taihe::copy_data_t{}, accountToken.data(), accountToken.size());
        AAFwk::WantParams getTokenParams;
        ani_env *env = get_env();
        auto parametersRef = AppExecFwk::WrapWantParams(env, option.getTokenParams_);
        GetDomainAccessTokenOptions domainAccessTokenOptions {
            .domainAccountInfo = ConvertToDomainAccountInfo(domainInfo),
            .domainAccountToken = taiheToken,
            .businessParams = reinterpret_cast<uintptr_t>(parametersRef),
            .callerUid = option.callingUid_,
        };
        jsPlugin_.GetAccessTokenSync(domainAccessTokenOptions);
    }

private:
    IUserAuthCallback ConvertToDomainAccountCallback(const std::shared_ptr<AccountSA::DomainAccountCallback> &callback)
    {
        ::taihe::callback<void(int32_t, ::ohos::account::osAccount::AuthResult const&)> onResultCallback =
        ::taihe::make_holder<OnResultCallbackImpl, ::taihe::callback<void(int32_t, ::ohos::account::osAccount::AuthResult const&)>>(callback);

        ::ohos::account::osAccount::IUserAuthCallback taiheCallback{
            .onResult = onResultCallback,
            .onAcquireInfo = std::nullopt,
        };
        return taiheCallback;
    }
private:
    DomainPlugin jsPlugin_;
};

class InputerManagerImpl {
public:
    InputerManagerImpl() {}
};

AccountManager getAccountManager()
{
    return make_holder<AccountManagerImpl, AccountManager>();
}

bool IsAuthenticationExpiredSync(const DomainAccountInfo &domainAccountInfo)
{
    AccountSA::DomainAccountInfo domainAccountInfoInner = ConvertToDomainAccountInfoInner(domainAccountInfo);
    bool isExpired = false;
    ErrCode errCode =
        AccountSA::DomainAccountClient::GetInstance().IsAuthenticationExpired(domainAccountInfoInner, isExpired);
    if (errCode != ERR_OK) {
        SetTaiheBusinessErrorFromNativeCode(errCode);
        return false;
    }
    return isExpired;
}

class THGetAccessTokenCallback : public AccountSA::GetAccessTokenCallback {
public:
    int32_t errorCode_ = -1;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::vector<uint8_t> accessToken_;
    bool onResultCalled_ = false;
    void OnResult(const int32_t errCode, const std::vector<uint8_t> &accessToken)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        if (this->onResultCalled_) {
            return;
        }
        this->onResultCalled_ = true;
        this->accessToken_ = accessToken;
        cv_.notify_one();
    }
};

array<uint8_t> GetAccessTokenSync(uintptr_t businessParams)
{
    AccountSA::DomainAccountInfo innerDomainInfo;
    AAFwk::WantParams innerGetTokenParams;
    array<uint8_t> accessToken = {};
    ani_env *env = get_env();
    ani_ref businessParamsRef = reinterpret_cast<ani_ref>(businessParams);
    auto status = AppExecFwk::UnwrapWantParams(env, businessParamsRef, innerGetTokenParams);
    if (status == false) {
        ACCOUNT_LOGE("Parameter error. The type of \"businessParams\" must be Record");
        SetTaiheBusinessErrorFromNativeCode(JSErrorCode::ERR_JS_PARAMETER_ERROR);
        return array<uint8_t>(taihe::copy_data_t{}, accessToken.data(), accessToken.size());
    }
    std::shared_ptr<THGetAccessTokenCallback> getAccessTokenCallback = std::make_shared<THGetAccessTokenCallback>();
    ErrCode errCode = AccountSA::DomainAccountClient::GetInstance().GetAccessToken(
        innerDomainInfo, innerGetTokenParams, getAccessTokenCallback);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("UpdateAccountTokenSync failed with errCode: %{public}d", errCode);
        SetTaiheBusinessErrorFromNativeCode(errCode);
        return array<uint8_t>(taihe::copy_data_t{}, accessToken.data(), accessToken.size());
    }
    std::unique_lock<std::mutex> lock(getAccessTokenCallback->mutex_);
    getAccessTokenCallback->cv_.wait(lock, [getAccessTokenCallback] { return getAccessTokenCallback->onResultCalled_;});
    if (getAccessTokenCallback->errorCode_ != ERR_OK) {
        ACCOUNT_LOGE("UpdateAccountTokenSync failed with errCode: %{public}d", getAccessTokenCallback->errorCode_);
        SetTaiheBusinessErrorFromNativeCode(getAccessTokenCallback->errorCode_);
        return array<uint8_t>(taihe::copy_data_t{}, accessToken.data(), accessToken.size());
    }
    return array<uint8_t>(taihe::copy_data_t{}, getAccessTokenCallback->accessToken_.data(),
        getAccessTokenCallback->accessToken_.size());
}

DomainServerConfig AddServerConfigSync(uintptr_t parameters)
{
    AccountSA::DomainServerConfig innerDomainServerConfig;
    DomainServerConfig emptyDomainServerConfig = {
        .parameters = 0,
        .id = string(""),
        .domain = string("")
    };
    std::string innerParameters = ConvertMapViewToStringInner(parameters);
    if (innerParameters == "") {
        ACCOUNT_LOGE("Get parameters failed.");
        SetTaiheBusinessErrorFromNativeCode(JSErrorCode::ERR_JS_PARAMETER_ERROR);
        return emptyDomainServerConfig;
    }
    ErrCode errCode = AccountSA::DomainAccountClient::GetInstance().AddServerConfig(
        innerParameters, innerDomainServerConfig);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("AddServerConfigSync failed with errCode: %{public}d", errCode);
        SetTaiheBusinessErrorFromNativeCode(errCode);
        return emptyDomainServerConfig;
    }
    return ConvertToDomainServerConfigTH(innerDomainServerConfig.id_,
                                         innerDomainServerConfig.domain_, innerDomainServerConfig.parameters_);
}

DomainServerConfig UpdateServerConfigSync(string_view configId, uintptr_t parameters)
{
    std::string innerConfigId(configId.data(), configId.size());
    AccountSA::DomainServerConfig innerDomainServerConfig;
    DomainServerConfig emptyDomainServerConfig = {
        .parameters = 0,
        .id = string(""),
        .domain = string("")
    };
    std::string innerParameters = ConvertMapViewToStringInner(parameters);
    if (innerParameters == "") {
        ACCOUNT_LOGE("Get parameters failed.");
        SetTaiheBusinessErrorFromNativeCode(JSErrorCode::ERR_JS_PARAMETER_ERROR);
        return emptyDomainServerConfig;
    }
    ErrCode errCode = AccountSA::DomainAccountClient::GetInstance().UpdateServerConfig(innerConfigId,
        innerParameters, innerDomainServerConfig);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("UpdateServerConfigSync failed with errCode: %{public}d", errCode);
        SetTaiheBusinessErrorFromNativeCode(errCode);
        return emptyDomainServerConfig;
    }
    return ConvertToDomainServerConfigTH(innerDomainServerConfig.id_,
                                         innerDomainServerConfig.domain_, innerDomainServerConfig.parameters_);
}

DomainServerConfig GetServerConfigSync(string_view configId)
{
    std::string innerConfigId(configId.data(), configId.size());
    AccountSA::DomainServerConfig innerDomainServerConfig;
    ErrCode errCode = AccountSA::DomainAccountClient::GetInstance().GetServerConfig(innerConfigId,
        innerDomainServerConfig);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("getServerConfigSync failed with errCode: %{public}d", errCode);
        SetTaiheBusinessErrorFromNativeCode(errCode);
        DomainServerConfig emptyDomainServerConfig = {
            .parameters = 0,
            .id = string(""),
            .domain = string("")
        };
        return emptyDomainServerConfig;
    }
    return ConvertToDomainServerConfigTH(innerDomainServerConfig.id_,
                                         innerDomainServerConfig.domain_, innerDomainServerConfig.parameters_);
}

array<DomainServerConfig> GetAllServerConfigsSync()
{
    std::vector<AccountSA::DomainServerConfig> innerDomainServerConfigs;
    std::vector<DomainServerConfig> domainServerConfigsVector;
    ErrCode errCode = AccountSA::DomainAccountClient::GetInstance().GetAllServerConfigs(innerDomainServerConfigs);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("GetAllServerConfigsSync failed with errCode: %{public}d", errCode);
        SetTaiheBusinessErrorFromNativeCode(errCode);
        return array<DomainServerConfig>(taihe::copy_data_t{}, domainServerConfigsVector.data(),
            domainServerConfigsVector.size());
    }
    for (const auto &innerDomainServerConfig : innerDomainServerConfigs) {
        auto domainServerConfig = ConvertToDomainServerConfigTH(innerDomainServerConfig.id_,
            innerDomainServerConfig.domain_, innerDomainServerConfig.parameters_);
        domainServerConfigsVector.push_back(domainServerConfig);
    }
    return array<DomainServerConfig>(taihe::copy_data_t{}, domainServerConfigsVector.data(),
    domainServerConfigsVector.size());
}

DomainServerConfig GetAccountServerConfigSync(DomainAccountInfo const &domainAccountInfo)
{
    AccountSA::DomainAccountInfo innerDomainAccountInfo = ConvertToDomainAccountInfoInner(domainAccountInfo);
    AccountSA::DomainServerConfig innerDomainServerConfig;
    ErrCode errCode = AccountSA::DomainAccountClient::GetInstance().GetAccountServerConfig(innerDomainAccountInfo,
                                                                                           innerDomainServerConfig);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("getAccountServerConfigSync failed with errCode: %{public}d", errCode);
        SetTaiheBusinessErrorFromNativeCode(errCode);
        DomainServerConfig emptyDomainServerConfig = {
            .parameters = 0,
            .id = string(""),
            .domain = string("")
        };
        return emptyDomainServerConfig;
    }
    return ConvertToDomainServerConfigTH(innerDomainServerConfig.id_,
                                         innerDomainServerConfig.domain_, innerDomainServerConfig.parameters_);
}

void RegisterPlugin(DomainPlugin plugin)
{
    std::shared_ptr<TaiheDomainPluginBridge> innerPlugin = std::make_shared<TaiheDomainPluginBridge>(plugin);
    int32_t errCode = AccountSA::DomainAccountClient::GetInstance().RegisterPlugin(innerPlugin);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("failed to register plugin, errCode=%{public}d", errCode);
        int32_t jsErrCode = AccountIAMConvertToJSErrCode(errCode);
        taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
    }
}

void RegisterInputer(AuthType authType, const IInputer &inputer)
{
    int32_t type = authType.get_value();
    auto taiheInputer = std::make_shared<TaiheIInputer>(inputer);
    auto taiheCallbackRef = std::make_shared<TaiheGetDataCallback>();
    taiheCallbackRef->inputer_ = taiheInputer;
    taiheCallbackRef->inputerData_ = std::make_shared<IInputData>(make_holder<IInputDataImpl, IInputData>());
    ErrCode errCode = AccountSA::AccountIAMClient::GetInstance().RegisterInputer(type, taiheCallbackRef);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to register inputer, errCode=%{public}d", errCode);
        int32_t jsErrCode = AccountIAMConvertToJSErrCode(errCode);
        taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
    }
}

void UnregisterInputer(AuthType authType)
{
    int32_t type = authType.get_value();
    ErrCode errCode = AccountSA::AccountIAMClient::GetInstance().UnregisterInputer(type);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to unregister inputer, errCode=%{public}d", errCode);
        int32_t jsErrCode = AccountIAMConvertToJSErrCode(errCode);
        taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
    }
}

UserIdentityManager CreateUserIdentityManager()
{
    return make_holder<UserIdentityManagerImpl, UserIdentityManager>();
}

UserAuth CreateUserAuth()
{
    return make_holder<UserAuthImpl, UserAuth>();
}

PINAuth CreatePINAuth()
{
    return make_holder<PINAuthImpl, PINAuth>();
}
} // namespace

TH_EXPORT_CPP_API_getAccountManager(getAccountManager);
TH_EXPORT_CPP_API_RegisterPlugin(RegisterPlugin);
TH_EXPORT_CPP_API_IsAuthenticationExpiredSync(IsAuthenticationExpiredSync);
TH_EXPORT_CPP_API_GetAccessTokenSync(GetAccessTokenSync);
TH_EXPORT_CPP_API_AddServerConfigSync(AddServerConfigSync);
TH_EXPORT_CPP_API_UpdateServerConfigSync(UpdateServerConfigSync);
TH_EXPORT_CPP_API_GetServerConfigSync(GetServerConfigSync);
TH_EXPORT_CPP_API_GetAllServerConfigsSync(GetAllServerConfigsSync);
TH_EXPORT_CPP_API_GetAccountServerConfigSync(GetAccountServerConfigSync);
TH_EXPORT_CPP_API_registerInputer(RegisterInputer);
TH_EXPORT_CPP_API_unregisterInputer(UnregisterInputer);
TH_EXPORT_CPP_API_CreateUserIdentityManager(CreateUserIdentityManager);
TH_EXPORT_CPP_API_CreateUserAuth(CreateUserAuth);
TH_EXPORT_CPP_API_CreatePINAuth(CreatePINAuth);
TH_EXPORT_CPP_API_createIInputData(createIInputData);
TH_EXPORT_CPP_API_getPtrByIInputData(getPtrByIInputData);