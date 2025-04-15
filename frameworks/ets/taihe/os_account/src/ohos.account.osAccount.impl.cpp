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
#include "account_error_no.h"
#include "account_error_no.h"
#include "account_iam_client.h"
#include "account_iam_info.h"
#include "os_account_info.h"
#include "os_account_manager.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"
#include "os_account_subscribe_info.h"

using namespace taihe;
using namespace ohos::account::osAccount;
using namespace ohos::account;
using namespace OHOS;
using my_callback = callback<void(int32_t)>;
namespace {
const std::string DAFAULT_STR = "";
const bool DEFAULT_BOOL = false;
const array<uint8_t> DEFAULT_ARRAY = array<uint8_t>::make(0);
const AccountSA::OsAccountType DEFAULT_ACCOUNT_TYPE = AccountSA::OsAccountType::END;

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

bool IsAccountIdValid(int32_t accountId)
{
    if (accountId < 0) {
        //ACCOUNT_LOGI("The account id is invalid");
        return false;
    }
    return true;
}

template<typename T>
T taiheReturn(ErrCode errCode, T result, const T defult) {
    if (errCode != ERR_OK) {
        int32_t jsErrCode = GenerateBusinessErrorCode(errCode);
        taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        return defult;
    }
    return result;
}

template<typename T>
T taiheIAMReturn(ErrCode errCode, T result, const T defult) {
    if (errCode != ERR_OK) {
        int32_t jsErrCode = AccountIAMConvertToJSErrCode(errCode);
        taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        return defult;
    }
    return result;
}
class SubscriberPtr : public AccountSA::OsAccountSubscriber {
    public:
        explicit SubscriberPtr(const AccountSA::OsAccountSubscribeInfo &subscribeInfo);
        ~SubscriberPtr() override;

        void OnAccountsChanged(const int &id) override;
        void OnAccountsSwitch(const int &newId, const int &oldId) override;
         std::shared_ptr<my_callback> ref_;

    private:
        void OnAccountsSubNotify(const int &newId, const int &oldId);

    };

SubscriberPtr::SubscriberPtr(const AccountSA::OsAccountSubscribeInfo &subscribeInfo) : OsAccountSubscriber(subscribeInfo)
{}

SubscriberPtr::~SubscriberPtr()
{}

void SubscriberPtr::OnAccountsChanged(const int &id)
{
    my_callback call = *ref_;
    call(id);
}

void SubscriberPtr::OnAccountsSwitch(const int &newId, const int &oldId)
{
    OsAccountSwitchEventData data = {oldId, newId};
    //OnAccountsSubNotify(newId, oldId);
}

void SubscriberPtr::OnAccountsSubNotify(const int &newId, const int &oldId)
{
   /*  std::shared_ptr<SubscriberOAWorker> subscriberOAWorker = std::make_shared<SubscriberOAWorker>();
    if (subscriberOAWorker == nullptr) {
        ACCOUNT_LOGE("insufficient memory for SubscriberAccountsWorker!");
        return;
    }
    subscriberOAWorker->oldId = oldId;
    subscriberOAWorker->newId = newId;
    subscriberOAWorker->env = env_;
    subscriberOAWorker->ref = ref_;
    subscriberOAWorker->subscriber = this;
    auto task = OnAccountsSubNotifyTask(subscriberOAWorker);
    if (napi_ok != napi_send_event(env_, task, napi_eprio_vip)) {
        ACCOUNT_LOGE("Post task failed");
        return;
    }
    ACCOUNT_LOGI("Post task finish"); */
}
struct UnsubscribeCBInfo   {
    UnsubscribeCBInfo(){}
    ~UnsubscribeCBInfo(){}
    AccountSA::OS_ACCOUNT_SUBSCRIBE_TYPE osSubscribeType = AccountSA::OS_ACCOUNT_SUBSCRIBE_TYPE::INVALID_TYPE;
    std::string name;
    std::shared_ptr<my_callback> callbackRef;
    std::shared_ptr<callback_view<void(OsAccountSwitchEventData const&)>> switchCallbackRef;
};
struct SubscribeCBInfo  {
    SubscribeCBInfo(){}
    ~SubscribeCBInfo(){}
    bool IsSameCallBack(AccountSA::OS_ACCOUNT_SUBSCRIBE_TYPE type, std::shared_ptr<my_callback> callbackRef,
        std::shared_ptr<callback_view<void(OsAccountSwitchEventData const&)>> switchCallbackRef);
    AccountSA::OS_ACCOUNT_SUBSCRIBE_TYPE osSubscribeType = AccountSA::OS_ACCOUNT_SUBSCRIBE_TYPE::INVALID_TYPE;
    std::string name;
    AccountSA::OsAccountManager *osManager = nullptr;
    std::shared_ptr<my_callback> callbackRef;
    std::shared_ptr<callback_view<void(OsAccountSwitchEventData const&)>> switchCallbackRef;
    std::shared_ptr<SubscriberPtr> subscriber = nullptr;
};

bool SubscribeCBInfo::IsSameCallBack(AccountSA::OS_ACCOUNT_SUBSCRIBE_TYPE type, std::shared_ptr<my_callback> callback,
    std::shared_ptr<callback_view<void(OsAccountSwitchEventData const&)>> switchCallback){
    if (type != osSubscribeType) {
        return false;
    }
    if (osSubscribeType == AccountSA::OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATED ||
        osSubscribeType == AccountSA::OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATING) {
        if(callbackRef.get() == callback.get()) {
            return true;
        } else {
            return false;
        }
    } else {
        if(switchCallback.get() == switchCallbackRef.get()) {
            return true;
        } else {
            return false;
        }
    }
}
std::mutex g_lockForOsAccountSubscribers;
std::map<AccountSA::OsAccountManager *, std::vector<SubscribeCBInfo *>> g_osAccountSubscribers;
class AccountManagerImpl {
private:
    AccountSA::OsAccountManager *osAccountManger_;
public:
    AccountManagerImpl() {
        osAccountManger_ = new (std::nothrow) AccountSA::OsAccountManager();
    }

    bool taiheIsMainOsAccount() {
        bool isMainOsAcount = false;
        OHOS::ErrCode errCode = AccountSA::OsAccountManager::IsMainOsAccount(isMainOsAcount);
        return taiheReturn(errCode, isMainOsAcount, DEFAULT_BOOL);
    }

    string taiheGetOsAccountProfilePhoto(int32_t localId) {
        std::string photo = "";
        OHOS::ErrCode errCode = AccountSA::OsAccountManager::GetOsAccountProfilePhoto(localId, photo);
        return taiheReturn(errCode, photo, DAFAULT_STR);
    }

    OsAccountType getOsAccountType() {
        AccountSA::OsAccountType type = DEFAULT_ACCOUNT_TYPE;
        OHOS::ErrCode errCode = AccountSA::OsAccountManager::GetOsAccountTypeFromProcess(type);
        return ConvertToOsAccountTypeKey(taiheReturn(errCode, type, DEFAULT_ACCOUNT_TYPE));
    }

    OsAccountType getOsAccountTypePromise(optional_view<int32_t> localId) {
        if (!localId) {
            return getOsAccountType();
        }
        AccountSA::OsAccountType type = DEFAULT_ACCOUNT_TYPE;
        OHOS::ErrCode errCode = AccountSA::OsAccountManager::GetOsAccountType(*localId, type);
        return ConvertToOsAccountTypeKey(taiheReturn(errCode, type, DEFAULT_ACCOUNT_TYPE));
    }

    static bool IsSubscribeInMap(SubscribeCBInfo *subscribeCBInfo)
    {
        std::lock_guard<std::mutex> lock(g_lockForOsAccountSubscribers);
        auto subscribe = g_osAccountSubscribers.find(subscribeCBInfo->osManager);
        if (subscribe == g_osAccountSubscribers.end()) {
            return false;
        }
        auto it = subscribe->second.begin();
        while (it != subscribe->second.end()) {
            if ((*it)->IsSameCallBack(subscribeCBInfo->osSubscribeType, subscribeCBInfo->callbackRef,
                subscribeCBInfo->switchCallbackRef)) {
                return true;
            }
            it++;
        }
        return false;
    }

    void Subscribe(SubscribeCBInfo *subscribeCBInfo){
        if (IsSubscribeInMap(subscribeCBInfo)) {
            delete subscribeCBInfo;
            return ;
        }
        ErrCode errCode = AccountSA::OsAccountManager::SubscribeOsAccount(subscribeCBInfo->subscriber);
        if (errCode != ERR_OK) {
            delete subscribeCBInfo;
            int32_t jsErrCode = GenerateBusinessErrorCode(errCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
            return;
        } else {
            std::lock_guard<std::mutex> lock(g_lockForOsAccountSubscribers);
            g_osAccountSubscribers[osAccountManger_].emplace_back(subscribeCBInfo);
        }
    }

    void onActivate(string_view name, callback_view<void(int32_t)> callback) {
        my_callback call = callback;
        AccountSA::OsAccountSubscribeInfo subscribeInfo(AccountSA::OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATED, name.data());
        SubscribeCBInfo *subscribeCBInfo = new (std::nothrow) SubscribeCBInfo();
        subscribeCBInfo->callbackRef = std::make_shared<my_callback>(call);
        subscribeCBInfo->subscriber = std::make_shared<SubscriberPtr>(subscribeInfo);
        subscribeCBInfo->osManager = osAccountManger_;
        Subscribe(subscribeCBInfo);
    }

    void onActivating(string_view name, callback_view<void(int32_t)> callback) {
        my_callback call = callback;
        AccountSA::OsAccountSubscribeInfo subscribeInfo(AccountSA::OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATED, name.data());
        SubscribeCBInfo *subscribeCBInfo = new (std::nothrow) SubscribeCBInfo();
        subscribeCBInfo->callbackRef = std::make_shared<my_callback>(call);
        subscribeCBInfo->subscriber = std::make_shared<SubscriberPtr>(subscribeInfo);
        subscribeCBInfo->osManager = osAccountManger_;
        Subscribe(subscribeCBInfo);
    }

    void Unsubscribe(UnsubscribeCBInfo *unsubscribeCBInfo)
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
            if (((unsubscribeCBInfo->osSubscribeType != osSubscribeType) || (unsubscribeCBInfo->name != name))){
                item++;
                continue;
            }
            if((unsubscribeCBInfo->callbackRef != nullptr || unsubscribeCBInfo->switchCallbackRef != nullptr) &&
                !((*item)->IsSameCallBack(unsubscribeCBInfo->osSubscribeType,unsubscribeCBInfo->callbackRef,
                unsubscribeCBInfo->switchCallbackRef))) {
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
            if (unsubscribeCBInfo->callbackRef != nullptr) {
                break;
            }
        }
        if (subscribe->second.empty()) {
            g_osAccountSubscribers.erase(subscribe->first);
        }
    }
    void offActivate(string_view name, optional_view<callback<void(int32_t)>> callback) {
        UnsubscribeCBInfo *unsubscribeCBInfo = new (std::nothrow) UnsubscribeCBInfo();
        if (unsubscribeCBInfo == nullptr) {
          //  ACCOUNT_LOGE("insufficient memory for unsubscribeCBInfo!");
            //return WrapVoidToJS(env);
            return;
        }
        unsubscribeCBInfo->name = name.data();
        unsubscribeCBInfo->osSubscribeType = AccountSA::OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATED;
        if (callback) {
            my_callback call = *callback;
            unsubscribeCBInfo->callbackRef = std::make_shared<my_callback>(call);
        }
        Unsubscribe(unsubscribeCBInfo);
        delete unsubscribeCBInfo;
        return;
    }

    void offActivating(string_view name, optional_view<callback<void(int32_t)>> callback) {
        UnsubscribeCBInfo *unsubscribeCBInfo = new (std::nothrow) UnsubscribeCBInfo();
        if (unsubscribeCBInfo == nullptr) {
          //  ACCOUNT_LOGE("insufficient memory for unsubscribeCBInfo!");
            //return WrapVoidToJS(env);
            return;
        }
        unsubscribeCBInfo->name = name.data();
        unsubscribeCBInfo->osSubscribeType = AccountSA::OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATING;
        if (callback) {
            my_callback call = *callback;
            unsubscribeCBInfo->callbackRef = std::make_shared<my_callback>(call);
        }
        Unsubscribe(unsubscribeCBInfo);
        delete unsubscribeCBInfo;
        return;
    }

    void onSwitching(callback_view<void(OsAccountSwitchEventData const&)> callback) {
        callback_view<void(OsAccountSwitchEventData const&)> call = callback;
        AccountSA::OsAccountSubscribeInfo subscribeInfo(AccountSA::OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHING, "");
        SubscribeCBInfo *subscribeCBInfo = new (std::nothrow) SubscribeCBInfo();
        subscribeCBInfo->switchCallbackRef = std::make_shared<callback_view<void(OsAccountSwitchEventData const&)>>(call);
        subscribeCBInfo->subscriber = std::make_shared<SubscriberPtr>(subscribeInfo);
        subscribeCBInfo->osManager = osAccountManger_;
        Subscribe(subscribeCBInfo);
    }

    void onSwitched(callback_view<void(OsAccountSwitchEventData const&)> callback) {
        callback_view<void(OsAccountSwitchEventData const&)> call = callback;
        AccountSA::OsAccountSubscribeInfo subscribeInfo(AccountSA::OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHED, "");
        SubscribeCBInfo *subscribeCBInfo = new (std::nothrow) SubscribeCBInfo();
        subscribeCBInfo->switchCallbackRef = std::make_shared<callback_view<void(OsAccountSwitchEventData const&)>>(call);
        subscribeCBInfo->subscriber = std::make_shared<SubscriberPtr>(subscribeInfo);
        subscribeCBInfo->osManager = osAccountManger_;
        Subscribe(subscribeCBInfo);
    }

    void offSwitching(optional_view<callback<void(OsAccountSwitchEventData const&)>> callback) {
        UnsubscribeCBInfo *unsubscribeCBInfo = new (std::nothrow) UnsubscribeCBInfo();
        if (unsubscribeCBInfo == nullptr) {
          //  ACCOUNT_LOGE("insufficient memory for unsubscribeCBInfo!");
            //return WrapVoidToJS(env);
            return;
        }

        unsubscribeCBInfo->osSubscribeType = AccountSA::OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHING;
        if (callback) {
            callback_view<void(OsAccountSwitchEventData const&)> call = *callback;
            unsubscribeCBInfo->switchCallbackRef = std::make_shared<callback_view<void(OsAccountSwitchEventData const&)>>(call);
        }
        Unsubscribe(unsubscribeCBInfo);
        delete unsubscribeCBInfo;
        return;
    }

    void offSwitched(optional_view<callback<void(OsAccountSwitchEventData const&)>> callback) {
        UnsubscribeCBInfo *unsubscribeCBInfo = new (std::nothrow) UnsubscribeCBInfo();
        if (unsubscribeCBInfo == nullptr) {
          //  ACCOUNT_LOGE("insufficient memory for unsubscribeCBInfo!");
            //return WrapVoidToJS(env);
            return;
        }

        unsubscribeCBInfo->osSubscribeType = AccountSA::OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHED;
        if (callback) {
            callback_view<void(OsAccountSwitchEventData const&)> call = *callback;
            unsubscribeCBInfo->switchCallbackRef = std::make_shared<callback_view<void(OsAccountSwitchEventData const&)>>(call);
        }
        Unsubscribe(unsubscribeCBInfo);
        delete unsubscribeCBInfo;
        return;
    }

    void activateOsAccountSync(int32_t localId) {
        TH_THROW(std::runtime_error, "activateOsAccountSync not implemented");
    }

    OsAccountInfo createOsAccountSync(string_view localName, OsAccountType type) {
        TH_THROW(std::runtime_error, "createOsAccountSync not implemented");
    }

    OsAccountInfo createOsAccountSync_(string_view localName, OsAccountType type, optional_view<CreateOsAccountOptions> options) {
        TH_THROW(std::runtime_error, "createOsAccountSync_ not implemented");
    }

    void deactivateOsAccountSync(int32_t localId) {
        TH_THROW(std::runtime_error, "deactivateOsAccountSync not implemented");
    }

    array<int32_t> getActivatedOsAccountLocalIdsSync() {
        TH_THROW(std::runtime_error, "getActivatedOsAccountLocalIdsSync not implemented");
    }

    OsAccountInfo getCurrentOsAccountSync() {
        TH_THROW(std::runtime_error, "getCurrentOsAccountSync not implemented");
    }

    int32_t getForegroundOsAccountLocalIdSync() {
        TH_THROW(std::runtime_error, "getForegroundOsAccountLocalIdSync not implemented");
    }

    int32_t getOsAccountLocalIdSync() {
        TH_THROW(std::runtime_error, "getOsAccountLocalIdSync not implemented");
    }

    int32_t getOsAccountLocalIdForUidSync(int32_t uid) {
        TH_THROW(std::runtime_error, "getOsAccountLocalIdForUidSync not implemented");
    }
};

class UserIdentityManagerImpl {
public:
    UserIdentityManagerImpl() {
        // Don't forget to implement the constructor.
    }

    array<uint8_t> openSession() {
        return openSessionPromise(nullptr);
    }

    array<uint8_t> openSessionPromise(optional_view<int32_t> accountId) {
        OHOS::ErrCode errCode = ERR_OK;
        int32_t userId = -1;
        if (accountId) {
            userId = *accountId;
        }
        if(!IsAccountIdValid(*accountId)) {
            taihe::set_business_error(ERR_JS_ACCOUNT_NOT_FOUND, ConvertToJsErrMsg(ERR_JS_ACCOUNT_NOT_FOUND));
            return DEFAULT_ARRAY;
        }
        std::vector<uint8_t> challenge;
        array<uint8_t> result = DEFAULT_ARRAY;
        errCode = AccountSA::AccountIAMClient::GetInstance().OpenSession(userId, challenge);
        if (errCode == ERR_OK) {
            result = taihe::array<uint8_t>(challenge.data(), challenge.size());
        }
        return taiheIAMReturn(errCode, result, DEFAULT_ARRAY);
    }

    void addCredential(CredentialInfo const& info, IIdmCallback const& callback) {
        TH_THROW(std::runtime_error, "addCredential not implemented");
    }

    void delUser(array_view<uint8_t> token, IIdmCallback const& callback) {
        TH_THROW(std::runtime_error, "delUser not implemented");
    }
};

class UserAuthImpl {
public:
    UserAuthImpl() {
        // Don't forget to implement the constructor.
    }
};


int32_t IsSystemApp()
{
     uint64_t tokenId = OHOS::IPCSkeleton::GetSelfTokenID();
    bool isSystemApp = OHOS::Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(tokenId);
    if (!isSystemApp) {
       // std::string errMsg = ConvertToJsErrMsg(ERR_JS_IS_NOT_SYSTEM_APP);
        //AccountNapiThrow(env, ERR_JS_IS_NOT_SYSTEM_APP, errMsg, true);
        return ERR_JS_IS_NOT_SYSTEM_APP;
    }
    return ERR_OK;
}
class IInputDataImpl {
public:
    std::shared_ptr<AccountSA::IInputerData> inputerData_;
public:
    IInputDataImpl() {
        // Don't forget to implement the constructor.
    }
    int64_t GetSpecificImplPtr() {
        return reinterpret_cast<int64_t>(this);
    }
    void onSetDataInner(AuthSubType authSubType, array_view<uint8_t> data) {
        int32_t jsErrCode = IsSystemApp();
        if ( jsErrCode != ERR_OK) {
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
    TaiheGetDataCallback(){}
    ~TaiheGetDataCallback(){}

    void OnGetData(int32_t authSubType, std::vector<uint8_t> challenge,
        const std::shared_ptr<AccountSA::IInputerData> inputerData) override {
            if (inputer == nullptr) {
                // ACCOUNT_LOGE("The onGetData function is undefined");
                return;
            }
            GetInputDataOptions option ={optional<array<uint8_t>>(std::in_place_t{}, challenge.data(), challenge.size())};
            inputer->onGetData(static_cast<AuthSubType::key_t>(authSubType), *inputerData_,
            option);
            reinterpret_cast<IInputDataImpl*>((*inputerData_)->GetSpecificImplPtr())->inputerData_ = inputerData;
    }

    std::shared_ptr<ohos::account::osAccount::IInputer> inputer;
    std::shared_ptr<IInputData> inputerData_;
private:
    //ThreadLockInfo lockInfo_;
};
void registerInputer(AuthType authType, IInputer const& inputer) {
    auto taiheInputer = std::make_shared<IInputer>(inputer);
    auto taiheCallbackRef = std::make_shared<TaiheGetDataCallback>();
    taiheCallbackRef->inputer = taiheInputer;
    taiheCallbackRef->inputerData_ = std::make_shared<IInputData>(make_holder<IInputDataImpl, IInputData>());
    ErrCode errCode = AccountSA::AccountIAMClient::GetInstance().RegisterInputer(authType, taiheCallbackRef);
    if (errCode != ERR_OK) {
        //ACCOUNT_LOGE("Failed to register inputer, errCode=%{public}d", errCode);
        int32_t jsErrCode = AccountIAMConvertToJSErrCode(errCode);
        taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
    }

}

class PINAuthImpl {
public:
    PINAuthImpl() {
        // Don't forget to implement the constructor.
    }

    void registerInputer(IInputer const& inputer) {
        auto taiheInputer = std::make_shared<IInputer>(inputer);
        auto taiheCallbackRef = std::make_shared<TaiheGetDataCallback>();
        taiheCallbackRef->inputer = taiheInputer;
        taiheCallbackRef->inputerData_ = std::make_shared<IInputData>(make_holder<IInputDataImpl, IInputData>());
        ErrCode errCode = AccountSA::AccountIAMClient::GetInstance().RegisterPINInputer(taiheCallbackRef);
        if (errCode != ERR_OK) {
            //ACCOUNT_LOGE("Failed to register inputer, errCode=%{public}d", errCode);
            int32_t jsErrCode = AccountIAMConvertToJSErrCode(errCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
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

