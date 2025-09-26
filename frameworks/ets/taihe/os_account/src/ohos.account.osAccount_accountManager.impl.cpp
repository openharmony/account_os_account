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
#include "ohos.account.distributedAccount.impl.hpp"
#include "ohos.account.distributedAccount.proj.hpp"
#include "ohos.account.osAccount.impl.hpp"
#include "ohos.account.osAccount.proj.hpp"
#include "ohos_account_kits.h"
#include "os_account_info.h"
#include "taihe_distributed_account_converter.h"
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
const std::string DEFAULT_STR = "";
const bool DEFAULT_BOOL = false;
const AccountSA::OsAccountType DEFAULT_ACCOUNT_TYPE = AccountSA::OsAccountType::END;
constexpr std::int32_t MAX_SUBSCRIBER_NAME_LEN = 1024;
std::mutex g_lockForOsAccountSubscribers;
std::map<AccountSA::OsAccountManager *, std::vector<AccountSA::SubscribeCBInfo *>> g_osAccountSubscribers;

template <typename T> T TaiheReturn(ErrCode errCode, T result, const T defult)
{
    if (errCode != ERR_OK) {
        int32_t jsErrCode = GenerateBusinessErrorCode(errCode);
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
            this->onResultCalled_ = true;
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
        return TaiheReturn(errCode, photo, DEFAULT_STR);
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
        if (subscribeCBInfo == nullptr) {
            ACCOUNT_LOGE("Insufficient memory for subscribeCBInfo!");
            return false;
        }
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
            ACCOUNT_LOGE("Insufficient memory for subscribeCBInfo!");
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
            int32_t errCode = AccountSA::OsAccountManager::UnsubscribeOsAccount((*item)->subscriber);
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

    int32_t GetOsAccountLocalIdForUidSyncTaihe(int32_t uid)
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

    void SetOsAccountProfilePhotoSync(int32_t localId, string_view photo)
    {
        std::string innerPhoto(photo.data(), photo.size());
        ErrCode errorCode = AccountSA::OsAccountManager::SetOsAccountProfilePhoto(localId, innerPhoto);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
    }

    int32_t GetOsAccountLocalIdForSerialNumberSync(int64_t serialNumber)
    {
        int id = -1;
        ErrCode errorCode = AccountSA::OsAccountManager::GetOsAccountLocalIdBySerialNumber(serialNumber, id);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        return id;
    }

    int32_t GetSerialNumberForOsAccountLocalIdSync(int32_t localId)
    {
        int64_t serialNum = -1;
        ErrCode errorCode = AccountSA::OsAccountManager::GetSerialNumberByOsAccountLocalId(localId, serialNum);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }

        return static_cast<int32_t>(serialNum);
    }

    int32_t GetBundleIdForUidWithIdSync(int32_t uid)
    {
        int id = -1;
        ErrCode errorCode = AccountSA::OsAccountManager::GetBundleIdFromUid(uid, id);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        return id;
    }

    int32_t GetBundleIdForUidSyncTaihe(int32_t uid)
    {
        int32_t bundleId = 0;
        ErrCode errorCode = AccountSA::OsAccountManager::GetBundleIdFromUid(uid, bundleId);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        return bundleId;
    }

    std::vector<ConstraintSourceTypeInfo> ConvertConstraintSourceTypeInfo(
        std::vector<AccountSA::ConstraintSourceTypeInfo> const& constraintSourceTypeInfos)
    {
        std::vector<ConstraintSourceTypeInfo> tempInfos;
        for (const auto& constraintSourceTypeInfo : constraintSourceTypeInfos) {
            ConstraintSourceType tempType = ConstraintSourceType::key_t::CONSTRAINT_NOT_EXIST;
            switch (constraintSourceTypeInfo.typeInfo) {
                case AccountSA::CONSTRAINT_NOT_EXIST:
                    tempType = ConstraintSourceType::key_t::CONSTRAINT_NOT_EXIST;
                    break;

                case AccountSA::CONSTRAINT_TYPE_BASE:
                    tempType = ConstraintSourceType::key_t::CONSTRAINT_TYPE_BASE;
                    break;

                case AccountSA::CONSTRAINT_TYPE_DEVICE_OWNER:
                    tempType = ConstraintSourceType::key_t::CONSTRAINT_TYPE_DEVICE_OWNER;
                    break;

                case AccountSA::CONSTRAINT_TYPE_PROFILE_OWNER:
                    tempType = ConstraintSourceType::key_t::CONSTRAINT_TYPE_PROFILE_OWNER;
                    break;

                default:
                    break;
            }

            ConstraintSourceTypeInfo tempInfo{
                .localId = constraintSourceTypeInfo.localId,
                .type = tempType,
            };
            tempInfos.push_back(tempInfo);
        }
        return tempInfos;
    }

    array<ConstraintSourceTypeInfo> GetOsAccountConstraintSourceTypesSync(int32_t localId, string_view constraint)
    {
        std::string innerConstraint(constraint.data(), constraint.size());
        std::vector<AccountSA::ConstraintSourceTypeInfo> constraintSourceTypeInfos;
        ErrCode errorCode = AccountSA::OsAccountManager::QueryOsAccountConstraintSourceTypes(localId,
            innerConstraint, constraintSourceTypeInfos);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        std::vector<ConstraintSourceTypeInfo> tempConstraintSourceTypeInfos =
            ConvertConstraintSourceTypeInfo(constraintSourceTypeInfos);
        return taihe::array<ConstraintSourceTypeInfo>(taihe::copy_data_t{}, tempConstraintSourceTypeInfos.data(),
            tempConstraintSourceTypeInfos.size());
    }

    bool CheckMultiOsAccountEnabledSync()
    {
        bool isMultiOAEnabled;
        ErrCode errCode = AccountSA::OsAccountManager::IsMultiOsAccountEnable(isMultiOAEnabled);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("CheckMultiOsAccountEnabledSync failed with errCode: %{public}d", errCode);
            SetTaiheBusinessErrorFromNativeCode(errCode);
        }
        return isMultiOAEnabled;
    }

    void RemoveOsAccountSync(int32_t localId)
    {
        ErrCode errCode = AccountSA::OsAccountManager::RemoveOsAccount(localId);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("RemoveOsAccountSync failed with errCode: %{public}d", errCode);
            SetTaiheBusinessErrorFromNativeCode(errCode);
        }
    }

    void SetOsAccountNameSync(int32_t localId, string_view localName)
    {
        std::string innerLocalName(localName.data(), localName.size());
        ErrCode errCode = AccountSA::OsAccountManager::SetOsAccountName(localId, innerLocalName);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("RemoveOsAccountSync failed with errCode: %{public}d", errCode);
            SetTaiheBusinessErrorFromNativeCode(errCode);
        }
    }

    bool IsOsAccountActivatedSync(int32_t localId)
    {
        bool isOsAccountActived;
        if (AccountSA::AccountPermissionManager::CheckSystemApp(false) != ERR_OK) {
            SetTaiheBusinessErrorFromNativeCode(ERR_JS_IS_NOT_SYSTEM_APP);
            return isOsAccountActived;
        }
        ErrCode errCode = AccountSA::OsAccountManager::IsOsAccountActived(localId, isOsAccountActived);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("IsOsAccountActivatedSync failed with errCode: %{public}d", errCode);
            SetTaiheBusinessErrorFromNativeCode(errCode);
        }
        return isOsAccountActived;
    }

    bool IsOsAccountConstraintEnabledSync(string_view constraint)
    {
        bool isConsEnabled;
        std::string innerConstraint(constraint.data(), constraint.size());
        std::vector<int> ids;
        ErrCode idErrCode = AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
        if (idErrCode != ERR_OK) {
            ACCOUNT_LOGE("IsOsAccountActivatedSync Get id failed", idErrCode);
            SetTaiheBusinessErrorFromNativeCode(idErrCode);
        }
        if (ids.empty()) {
            ACCOUNT_LOGE("No Active OsAccount Ids");
            SetTaiheBusinessErrorFromNativeCode(idErrCode);
        }
        ErrCode errCode = AccountSA::OsAccountManager::CheckOsAccountConstraintEnabled(ids[0],
            innerConstraint, isConsEnabled);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("IsOsAccountActivatedSync failed with errCode: %{public}d", errCode);
            SetTaiheBusinessErrorFromNativeCode(errCode);
        }
        return isConsEnabled;
    }

    bool IsOsAccountConstraintEnabledWithId(int32_t localId, string_view constraint)
    {
        bool isConsEnabled;
        if (AccountSA::AccountPermissionManager::CheckSystemApp(false) != ERR_OK) {
            SetTaiheBusinessErrorFromNativeCode(ERR_JS_IS_NOT_SYSTEM_APP);
            return isConsEnabled;
        }
        std::string innerConstraint(constraint.data(), constraint.size());
        ErrCode errCode = AccountSA::OsAccountManager::CheckOsAccountConstraintEnabled(localId,
            innerConstraint, isConsEnabled);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("IsOsAccountConstraintEnabledWithId failed with errCode: %{public}d", errCode);
            SetTaiheBusinessErrorFromNativeCode(errCode);
        }
        return isConsEnabled;
    }

    bool CheckOsAccountTestableSync()
    {
        return false;
    }

    void SetOsAccountConstraintsSync(int32_t localId, array_view<taihe::string> constraints, bool enable)
    {
        std::vector<std::string> innerConstraints;
        for (const auto &constraint : constraints) {
            std::string innerConstraint(constraint.data(), constraint.size());
            innerConstraints.push_back(innerConstraint);
        }
        ErrCode errCode =
        AccountSA::OsAccountManager::SetOsAccountConstraints(localId, innerConstraints, enable);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("SetOsAccountConstraintsSync failed with errCode: %{public}d", errCode);
            SetTaiheBusinessErrorFromNativeCode(errCode);
        }
    }

    taihe::string GetOsAccountNameSync()
    {
        std::string name;
        ErrCode errCode = AccountSA::OsAccountManager::GetOsAccountName(name);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("GetOsAccountNameSync failed with errCode: %{public}d", errCode);
            SetTaiheBusinessErrorFromNativeCode(errCode);
        }
        return taihe::string(name);
    }

    uint32_t GetOsAccountCountSync()
    {
        unsigned int osAccountsCount;
        ErrCode errCode = AccountSA::OsAccountManager::GetCreatedOsAccountsCount(osAccountsCount);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("GetOsAccountCountSync failed with errCode: %{public}d", errCode);
            SetTaiheBusinessErrorFromNativeCode(errCode);
        }
        return osAccountsCount;
    }

    int32_t GetOsAccountLocalIdForUidSyncOverload(int32_t uid)
    {
        int32_t localId = 0;
        ErrCode errCode = AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, localId);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("GetOsAccountLocalIdForUidSyncOverload failed with errCode: %{public}d", errCode);
            SetTaiheBusinessErrorFromNativeCode(errCode);
        }
        return localId;
    }

    int32_t GetOsAccountLocalIdForDomainSync(DomainAccountInfo const& domainInfo)
    {
        int32_t id = 0;
        std::string innerDomain (domainInfo.domain.data(), domainInfo.domain.size());
        std::string innerAccountName (domainInfo.accountName.data(), domainInfo.accountName.size());
        AccountSA::DomainAccountInfo innerDomainInfo;
        innerDomainInfo.domain_ = innerDomain;
        innerDomainInfo.accountName_ = innerAccountName;
        if (domainInfo.accountId.has_value()) {
            std::string innerAccountId (domainInfo.accountId.value().data(), domainInfo.accountId.value().size());
            innerDomainInfo.accountId_ = innerAccountId;
        }

        if (domainInfo.isAuthenticated.has_value()) {
            innerDomainInfo.isAuthenticated = domainInfo.isAuthenticated.value();
        }

        if (domainInfo.serverConfigId.has_value()) {
            innerDomainInfo.serverConfigId_ = domainInfo.serverConfigId.value();
        }

        ErrCode errCode = AccountSA::OsAccountManager::GetOsAccountLocalIdFromDomain(innerDomainInfo, id);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("GetOsAccountLocalIdForDomainSync failed with errCode: %{public}d", errCode);
            SetTaiheBusinessErrorFromNativeCode(errCode);
        }
        return id;
    }

    uint32_t QueryMaxOsAccountNumberSync()
    {
        uint32_t maxOsAccountNumber;
        ErrCode errCode = AccountSA::OsAccountManager::QueryMaxOsAccountNumber(maxOsAccountNumber);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("QueryMaxOsAccountNumberSync failed with errCode: %{public}d", errCode);
            SetTaiheBusinessErrorFromNativeCode(errCode);
        }
        return maxOsAccountNumber;
    }

    array<string> GetEnabledOsAccountConstraintsSync(int32_t localId)
    {
        std::vector<std::string> innerConstraints;
        if (AccountSA::AccountPermissionManager::CheckSystemApp(false) != ERR_OK) {
            SetTaiheBusinessErrorFromNativeCode(ERR_JS_IS_NOT_SYSTEM_APP);
            return taihe::array<string>(taihe::copy_data_t{}, innerConstraints.data(), innerConstraints.size());
        }
        ErrCode errCode = AccountSA::OsAccountManager::GetOsAccountAllConstraints(localId, innerConstraints);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("GetEnabledOsAccountConstraintsSync failed with errCode: %{public}d", errCode);
            SetTaiheBusinessErrorFromNativeCode(errCode);
        }
        return taihe::array<string>(taihe::copy_data_t{}, innerConstraints.data(), innerConstraints.size());
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
            AccountSA::OsAccountInfo emptyOsAccountInfo;
            return ConvertOsAccountInfo(emptyOsAccountInfo);
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
            AccountSA::OsAccountInfo emptyOsAccountInfo;
            return ConvertOsAccountInfo(emptyOsAccountInfo);
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

    DomainAccountInfo GetOsAccountDomainInfoSync(int32_t localId)
    {
        AccountSA::DomainAccountInfo innerDomainInfo;
        ErrCode errCode = AccountSA::OsAccountManager::GetOsAccountDomainInfo(localId, innerDomainInfo);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("GetOsAccountDomainInfoSync failed with errCode: %{public}d", errCode);
            SetTaiheBusinessErrorFromNativeCode(errCode);
        }
        DomainAccountInfo domainAccountInfo = DomainAccountInfo {
            .domain = innerDomainInfo.domain_,
            .accountName = innerDomainInfo.accountName_,
            .accountId = optional<string>(std::in_place, innerDomainInfo.accountId_),
            .isAuthenticated = optional<bool>(std::in_place, innerDomainInfo.isAuthenticated),
            .serverConfigId = optional<string>(std::in_place, innerDomainInfo.serverConfigId_),
        };
        return domainAccountInfo;
    }

    string QueryDistributedVirtualDeviceIdSync()
    {
        std::string deviceId;
        ErrCode errCode = AccountSA::OsAccountManager::GetDistributedVirtualDeviceId(deviceId);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("QueryDistributedVirtualDeviceIdSync failed with errCode: %{public}d", errCode);
            SetTaiheBusinessErrorFromNativeCode(errCode);
        }
        return string(deviceId);
    }
};

AccountManager GetAccountManager()
{
    return make_holder<AccountManagerImpl, AccountManager>();
}


} // namespace

TH_EXPORT_CPP_API_GetAccountManager(GetAccountManager);
