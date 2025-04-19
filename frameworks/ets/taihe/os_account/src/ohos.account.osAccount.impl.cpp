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

#include <map>
#include <mutex>
#include <vector>
#include "ohos.account.osAccount.proj.hpp"
#include "ohos.account.osAccount.impl.hpp"
#include "taihe/runtime.hpp"
#include "taihe/string.hpp"
#include "stdexcept"
#include "account_log_wrapper.h"
#include "os_account_info.h"
#include "taihe_common.h"
#include "taihe_account_info.h"

using namespace taihe;
using namespace ohos::account::osAccount;
using namespace ohos::account;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string DAFAULT_STR = "";
const bool DEFAULT_BOOL = false;
const array<uint8_t> DEFAULT_ARRAY = array<uint8_t>::make(0);
const AccountSA::OsAccountType DEFAULT_ACCOUNT_TYPE = AccountSA::OsAccountType::END;
constexpr std::int32_t MAX_SUBSCRIBER_NAME_LEN = 1024;

template<typename T>
T taiheReturn(ErrCode errCode, T result, const T defult)
{
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Return error!");
        int32_t jsErrCode = GenerateBusinessErrorCode(errCode);
        taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        return defult;
    }
    return result;
}

template<typename T>
T taiheIAMReturn(ErrCode errCode, T result, const T defult)
{
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Return error!");
        int32_t jsErrCode = AccountIAMConvertToJSErrCode(errCode);
        taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        return defult;
    }
    return result;
}


std::mutex g_lockForOsAccountSubscribers;
std::map<OsAccountManager *, std::vector<SubscribeCBInfo *>> g_osAccountSubscribers;

class AccountManagerImpl {
private:
    OsAccountManager *osAccountManger_;
public:
    AccountManagerImpl()
    {
        osAccountManger_ = new (std::nothrow) OsAccountManager();
    }

    bool TaiheIsMainOsAccount()
    {
        bool isMainOsAcount = false;
        OHOS::ErrCode errCode = OsAccountManager::IsMainOsAccount(isMainOsAcount);
        return taiheReturn(errCode, isMainOsAcount, DEFAULT_BOOL);
    }

    string TaiheGetOsAccountProfilePhoto(double localId)
    {
        int32_t temp = static_cast<int32_t>(localId);
        std::string photo = "";
        OHOS::ErrCode errCode = OsAccountManager::GetOsAccountProfilePhoto(temp, photo);
        return taiheReturn(errCode, photo, DAFAULT_STR);
    }

    TaiheOsAccountType TaiheGetOsAccountType()
    {
        AccountSA::OsAccountType type = DEFAULT_ACCOUNT_TYPE;
        OHOS::ErrCode errCode = OsAccountManager::GetOsAccountTypeFromProcess(type);
        return ConvertToOsAccountTypeKey(taiheReturn(errCode, type, DEFAULT_ACCOUNT_TYPE));
    }

    TaiheOsAccountType TaiheGetOsAccountTypeWithId(double localId)
    {
        AccountSA::OsAccountType type = DEFAULT_ACCOUNT_TYPE;
        int32_t temp = static_cast<int32_t>(localId);
        OHOS::ErrCode errCode = OsAccountManager::GetOsAccountType(temp, type);
        return ConvertToOsAccountTypeKey(taiheReturn(errCode, type, DEFAULT_ACCOUNT_TYPE));
    }

    static bool IsSubscribeInMap(SubscribeCBInfo *subscribeCBInfo)
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

    void Subsribe(std::string name, OS_ACCOUNT_SUBSCRIBE_TYPE type,
        std::shared_ptr<active_callback> activeCallback, std::shared_ptr<switch_callback> switchCallback)
    {
        SubscribeCBInfo *subscribeCBInfo = new (std::nothrow) SubscribeCBInfo();
        if (subscribeCBInfo == nullptr) {
            ACCOUNT_LOGE("insufficient memory for subscribeCBInfo!");
            return;
        }
        subscribeCBInfo->activeCallbackRef = activeCallback;
        subscribeCBInfo->switchCallbackRef = switchCallback;
        OsAccountSubscribeInfo subscribeInfo(type, name);
        subscribeCBInfo->subscriber = std::make_shared<TaiheSubscriberPtr>(subscribeInfo);
        subscribeCBInfo->osManager = osAccountManger_;
        subscribeCBInfo->osSubscribeType = type;
        if (IsSubscribeInMap(subscribeCBInfo)) {
            ACCOUNT_LOGE("Has in map.");
            delete subscribeCBInfo;
            return;
        }
        ErrCode errCode = OsAccountManager::SubscribeOsAccount(subscribeCBInfo->subscriber);
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

    void OnActivate(string_view name, callback_view<void(double)> callback)
    {
        if (name.size() == 0 || name.size() > MAX_SUBSCRIBER_NAME_LEN) {
            ACCOUNT_LOGE("Subscriber name size %{public}zu is invalid.", name.size());
            std::string errMsg = "Parameter error. The length of \"name\" is invalid";
            taihe::set_business_error(ERR_JS_INVALID_PARAMETER, errMsg);
            return;
        }
        active_callback call = callback;
        Subsribe(name.data(), OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATED,
            std::make_shared<active_callback>(call), nullptr);
    }

    void OnActivating(string_view name, callback_view<void(double)> callback)
    {
        if (name.size() == 0 || name.size() > MAX_SUBSCRIBER_NAME_LEN) {
            ACCOUNT_LOGE("Subscriber name size %{public}zu is invalid.", name.size());
            std::string errMsg = "Parameter error. The length of \"name\" is invalid";
            taihe::set_business_error(ERR_JS_INVALID_PARAMETER, errMsg);
            return;
        }
        active_callback call = callback;
        Subsribe(name.data(), OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATING,
            std::make_shared<active_callback>(call), nullptr);
    }

    void OnSwitching(callback_view<void(OsAccountSwitchEventData const&)> callback)
    {
        switch_callback call = callback;
        Subsribe("", OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHING, nullptr,
            std::make_shared<switch_callback>(call));
    }

    void OnSwitched(callback_view<void(OsAccountSwitchEventData const&)> callback)
    {
        switch_callback call = callback;
        Subsribe("", OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHED, nullptr,
            std::make_shared<switch_callback>(call));
    }

    void Unsubscribe(std::string unsubscribeName, OS_ACCOUNT_SUBSCRIBE_TYPE type,
        std::shared_ptr<active_callback> activeCallback, std::shared_ptr<switch_callback> switchCallback)
    {
        std::lock_guard<std::mutex> lock(g_lockForOsAccountSubscribers);
        auto subscribe = g_osAccountSubscribers.find(osAccountManger_);
        if (subscribe == g_osAccountSubscribers.end()) {
            return;
        }
        auto item = subscribe->second.begin();
        while (item != subscribe->second.end()) {
            OsAccountSubscribeInfo subscribeInfo;
            OS_ACCOUNT_SUBSCRIBE_TYPE osSubscribeType;
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
            int errCode = OsAccountManager::UnsubscribeOsAccount((*item)->subscriber);
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

    void OffActivate(string_view name, optional_view<callback<void(double)>> callback)
    {
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
        Unsubscribe(name.data(), OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATED, activeCallback, nullptr);
        return;
    }

    void OffActivating(string_view name, optional_view<callback<void(double)>> callback)
    {
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
        Unsubscribe(name.data(), OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATING, activeCallback, nullptr);
        return;
    }

    void OffSwitching(optional_view<callback<void(OsAccountSwitchEventData const&)>> callback)
    {
        std::shared_ptr<switch_callback> switchCallback = nullptr;
        if (callback) {
            switch_callback call = *callback;
            switchCallback = std::make_shared<switch_callback>(call);
        }
        Unsubscribe("", OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHING, nullptr, switchCallback);
        return;
    }

    void OffSwitched(optional_view<callback<void(OsAccountSwitchEventData const&)>> callback)
    {
        std::shared_ptr<switch_callback> switchCallback = nullptr;
        if (callback) {
            switch_callback call = *callback;
            switchCallback = std::make_shared<switch_callback>(call);
        }
        Unsubscribe("", OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHED, nullptr, switchCallback);
        return;
    }

    void ActivateOsAccountSync(int32_t localId)
    {
        TH_THROW(std::runtime_error, "activateOsAccountSync not implemented");
    }

    TaiheOsAccountInfo CreateOsAccountSync(string_view localName, TaiheOsAccountType type)
    {
        TH_THROW(std::runtime_error, "createOsAccountSync not implemented");
    }

    TaiheOsAccountInfo CreateOsAccountSync_(string_view localName, TaiheOsAccountType type,
        optional_view<TaiheCreateOsAccountOptions> options)
    {
        TH_THROW(std::runtime_error, "createOsAccountSync_ not implemented");
    }

    void DeactivateOsAccountSync(int32_t localId)
    {
        TH_THROW(std::runtime_error, "deactivateOsAccountSync not implemented");
    }

    array<int32_t> GetActivatedOsAccountLocalIdsSync()
    {
        TH_THROW(std::runtime_error, "getActivatedOsAccountLocalIdsSync not implemented");
    }

    TaiheOsAccountInfo GetCurrentOsAccountSync()
    {
        TH_THROW(std::runtime_error, "getCurrentOsAccountSync not implemented");
    }

    int32_t GetForegroundOsAccountLocalIdSync()
    {
        TH_THROW(std::runtime_error, "getForegroundOsAccountLocalIdSync not implemented");
    }

    int32_t GetOsAccountLocalIdSync()
    {
        TH_THROW(std::runtime_error, "getOsAccountLocalIdSync not implemented");
    }

    int32_t GetOsAccountLocalIdForUidSync(int32_t uid)
    {
        TH_THROW(std::runtime_error, "getOsAccountLocalIdForUidSync not implemented");
    }
};

class UserIdentityManagerImpl {
public:
    UserIdentityManagerImpl()
    {
        // Don't forget to implement the constructor.
    }

    array<uint8_t> OpenSession()
    {
        return OpenSessionPromise(nullptr);
    }

    array<uint8_t> OpenSessionPromise(optional_view<int32_t> accountId)
    {
        OHOS::ErrCode errCode = ERR_OK;
        int32_t userId = -1;
        if (accountId) {
            userId = *accountId;
        }
        if (!IsAccountIdValid(*accountId)) {
            taihe::set_business_error(ERR_JS_ACCOUNT_NOT_FOUND, ConvertToJsErrMsg(ERR_JS_ACCOUNT_NOT_FOUND));
            return DEFAULT_ARRAY;
        }
        std::vector<uint8_t> challenge;
        array<uint8_t> result = DEFAULT_ARRAY;
        errCode = AccountIAMClient::GetInstance().OpenSession(userId, challenge);
        if (errCode == ERR_OK) {
            result = taihe::array<uint8_t>(challenge.data(), challenge.size());
        }
        return taiheIAMReturn(errCode, result, DEFAULT_ARRAY);
    }

    void addCredential(TaiheCredentialInfo const& info, IIdmCallback const& callback)
    {
        TH_THROW(std::runtime_error, "addCredential not implemented");
    }

    void delUser(array_view<uint8_t> token, IIdmCallback const& callback)
    {
        TH_THROW(std::runtime_error, "delUser not implemented");
    }
};

class UserAuthImpl {
public:
    UserAuthImpl()
    {
        // Don't forget to implement the constructor.
    }
};

class IInputDataImpl {
public:
    std::shared_ptr<IInputerData> inputerData_;
public:
    IInputDataImpl()
    {
        // Don't forget to implement the constructor.
    }

    int64_t GetSpecificImplPtr()
    {
        return reinterpret_cast<int64_t>(this);
    }

    void onSetDataInner(AuthSubType authSubType, array_view<uint8_t> data)
    {
        ACCOUNT_LOGE("start!");
        int32_t jsErrCode = IsSystemApp();
        if (jsErrCode != ERR_OK) {
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
            return;
        }
        std::vector<uint8_t> authTokenVec(data.data(), data.data() + data.size());
        inputerData_->OnSetData(static_cast<int32_t>(authSubType), authTokenVec);
        inputerData_ = nullptr;
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
    ACCOUNT_LOGE("start!");
    if (inputer_ == nullptr) {
        ACCOUNT_LOGE("The onGetData function is undefined");
        return;
    }
    GetInputDataOptions option = {optional<array<uint8_t>>(std::in_place_t{}, challenge.data(), challenge.size())};
    reinterpret_cast<IInputDataImpl*>((*inputerData_)->GetSpecificImplPtr())->inputerData_ = inputerData;
    inputer_->onGetData(static_cast<AuthSubType::key_t>(authSubType), *inputerData_, option);
}

class PINAuthImpl {
public:
    PINAuthImpl()
    {
        // Don't forget to implement the constructor.
    }

    void registerInputer(TaiheIInputer const& inputer)
    {
        ACCOUNT_LOGE("start!");
        auto taiheInputer = std::make_shared<TaiheIInputer>(inputer);
        auto taiheCallbackRef = std::make_shared<TaiheGetDataCallback>();
        taiheCallbackRef->inputer_ = taiheInputer;
        taiheCallbackRef->inputerData_ = std::make_shared<IInputData>(make_holder<IInputDataImpl, IInputData>());
        ErrCode errCode = AccountIAMClient::GetInstance().RegisterPINInputer(taiheCallbackRef);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("Failed to register inputer, errCode=%{public}d", errCode);
            int32_t jsErrCode = AccountIAMConvertToJSErrCode(errCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
    }
};

class InputerManagerImpl {
public:
    InputerManagerImpl()
    {
        // Don't forget to implement the constructor.
    }
};

void registerInputer(TaiheAuthType authType, TaiheIInputer const& inputer)
{
    ACCOUNT_LOGE("start!");
    auto taiheInputer = std::make_shared<TaiheIInputer>(inputer);
    auto taiheCallbackRef = std::make_shared<TaiheGetDataCallback>();
    taiheCallbackRef->inputer_ = taiheInputer;
    taiheCallbackRef->inputerData_ = std::make_shared<IInputData>(make_holder<IInputDataImpl, IInputData>());
    ErrCode errCode = AccountIAMClient::GetInstance().RegisterInputer(authType, taiheCallbackRef);
    ACCOUNT_LOGE("end!");
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to register inputer, errCode=%{public}d", errCode);
        int32_t jsErrCode = AccountIAMConvertToJSErrCode(errCode);
        taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
    }
}

AccountManager getAccountManager()
{
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<AccountManagerImpl, AccountManager>();
}

UserIdentityManager createUserIdentityManager()
{
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<UserIdentityManagerImpl, UserIdentityManager>();
}

UserAuth createUserAuth()
{
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<UserAuthImpl, UserAuth>();
}

PINAuth createPINAuth()
{
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
