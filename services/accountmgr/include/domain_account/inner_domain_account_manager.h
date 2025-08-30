/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_SERVICES_DOMAIN_ACCOUNT_INCLUDE_INNER_DOMAIN_ACCOUNT_MANAGER_H
#define OS_ACCOUNT_SERVICES_DOMAIN_ACCOUNT_INCLUDE_INNER_DOMAIN_ACCOUNT_MANAGER_H

#include <condition_variable>
#include <mutex>
#include "domain_account_auth_death_recipient.h"
#include "domain_account_common.h"
#include "domain_account_plugin_death_recipient.h"
#include "domain_account_callback.h"
#include "domain_account_callback_stub.h"
#include "domain_plugin.h"
#include "idomain_account_plugin.h"
#include "int_wrapper.h"
#include "bool_wrapper.h"
#include "os_account_info.h"
#include "want.h"

namespace OHOS {
namespace AccountSA {
class InnerDomainAuthCallback;
class InnerDomainAccountManager {
public:
    static InnerDomainAccountManager &GetInstance();
    ErrCode RegisterPlugin(const sptr<IDomainAccountPlugin> &plugin);
    ErrCode UnregisterPlugin();
    ErrCode Auth(const DomainAccountInfo &info, const std::vector<uint8_t> &password,
        const sptr<IDomainAccountCallback> &callback);
    ErrCode AuthUser(int32_t userId, const std::vector<uint8_t> &password,
        const sptr<IDomainAccountCallback> &callback);
    void AuthResultInfoCallback(uint64_t contextId, PluginAuthResultInfo *authResultInfo, PluginBussnessError *error);
    ErrCode CancelAuth(const sptr<IDomainAccountCallback> &callback);
    ErrCode CancelAuth(const uint64_t &contextId);
    ErrCode AuthWithPopup(int32_t userId, const sptr<IDomainAccountCallback> &callback);
    ErrCode AuthWithToken(int32_t userId, const std::vector<uint8_t> &token);
    ErrCode GetAuthStatusInfo(const DomainAccountInfo &info, const std::shared_ptr<DomainAccountCallback> &callback);
    ErrCode HasDomainAccount(const DomainAccountInfo &info, const sptr<IDomainAccountCallback> &callback);
    ErrCode UpdateAccountToken(const DomainAccountInfo &info, const std::vector<uint8_t> &token);
    ErrCode IsAuthenticationExpired(const DomainAccountInfo &info, bool &isExpired);
    ErrCode SetAccountPolicy(const DomainAccountInfo &info, const std::string &policy);
    ErrCode GetAccessToken(const DomainAccountInfo &info, const AAFwk::WantParams &parameters,
        const sptr<IDomainAccountCallback> &callback);
    ErrCode GetDomainAccountInfo(const DomainAccountInfo &info, DomainAccountInfo &result);
    ErrCode GetDomainAccountInfo(const DomainAccountInfo &info, const sptr<IDomainAccountCallback> &callback);
    ErrCode OnAccountBound(const DomainAccountInfo &info, const int32_t localId,
        const std::shared_ptr<DomainAccountCallback> &callback);
    ErrCode IsAccountTokenValid(const AccountSA::DomainAccountInfo &info, const std::vector<uint8_t> &token,
        const std::shared_ptr<DomainAccountCallback> &callback);
    ErrCode OnAccountUnBound(const DomainAccountInfo &info, const std::shared_ptr<DomainAccountCallback> &callback,
        const int32_t localId);
    bool IsPluginAvailable();
    void InsertTokenToMap(int32_t userId, const std::vector<uint8_t> &token);
    bool GetTokenFromMap(int32_t userId, std::vector<uint8_t> &token);
    void RemoveTokenFromMap(int32_t userId);
    ErrCode GetAccountStatus(const DomainAccountInfo &info, DomainAccountStatus &status);
    ErrCode RegisterAccountStatusListener(const sptr<IDomainAccountCallback> &listener);
    ErrCode UnregisterAccountStatusListener(const sptr<IDomainAccountCallback> &listener);
    void NotifyDomainAccountEvent(
        int32_t userId, DomainAccountEvent event, DomainAccountStatus status, const DomainAccountInfo &info);
    ErrCode GetDomainAccountInfoByUserId(int32_t userId, DomainAccountInfo &domainInfo);
    ErrCode AddServerConfig(const std::string &paremters, DomainServerConfig &config);
    ErrCode RemoveServerConfig(const std::string &configId);
    ErrCode UpdateServerConfig(const std::string &configId, const std::string &paremters, DomainServerConfig &config);
    ErrCode GetServerConfig(const std::string &configId, DomainServerConfig &config);
    ErrCode GetAllServerConfigs(std::vector<DomainServerConfig> &configs);
    ErrCode GetAccountServerConfig(const DomainAccountInfo &info, DomainServerConfig &config);
    ErrCode GetAccountServerConfig(const std::string &accountName, const std::string &configId,
        DomainServerConfig &config);
    void LoaderLib(const std::string &path, const std::string &libName);
    void CloseLib();
    ErrCode UpdateAccountInfo(const DomainAccountInfo &oldAccountInfo, const DomainAccountInfo &newAccountInfo);
    ErrCode GetAccountPolicy(const DomainAccountInfo &info, std::string &policy);
    ErrCode UnbindDomainAccountSync(const DomainAccountInfo &info, const int32_t localId);
    ErrCode BindDomainAccountSync(const DomainAccountInfo &info, const int32_t localId);
    ErrCode GetDomainAccountInfoSync(const int32_t localId, const DomainAccountInfo &info, DomainAccountInfo &fullInfo);

    ErrCode CheckAndRecoverBindDomainForUncomplete(const OsAccountInfo &accountInfo);

    ErrCode BindDomainAccount(const int32_t localId,
        const DomainAccountInfo &domainInfo, const sptr<IDomainAccountCallback> &callback);
    ErrCode CleanUnbindDomainAccount();

    ErrCode CheckOsAccountCanBindDomainAccount(const OsAccountInfo &osAccountInfo);
    ErrCode CheckDomainAccountCanBindOsAccount(const DomainAccountInfo &domainInfo);
private:
    InnerDomainAccountManager();
    ~InnerDomainAccountManager();
    bool GenerateContextId(uint64_t &contextId);
    DISALLOW_COPY_AND_MOVE(InnerDomainAccountManager);
    void StartIsAccountTokenValid(const sptr<IDomainAccountPlugin> &plugin, const AccountSA::DomainAccountInfo &info,
        const std::vector<uint8_t> &token, const sptr<IDomainAccountCallback> &callback);
    void StartGetDomainAccountInfo(const sptr<IDomainAccountPlugin> &plugin,
        const GetDomainAccountInfoOptions &options, const sptr<IDomainAccountCallback> &callback);
    void StartOnAccountUnBound(const sptr<IDomainAccountPlugin> &plugin, const DomainAccountInfo &info,
        const sptr<IDomainAccountCallback> &callback);
    void StartOnAccountBound(const sptr<IDomainAccountPlugin> &plugin, const DomainAccountInfo &info,
        const int32_t localId, const sptr<IDomainAccountCallback> &callback);
    ErrCode StartGetAccessToken(const sptr<IDomainAccountPlugin> &plugin, const std::vector<uint8_t> &accountToken,
        const DomainAccountInfo &info, const GetAccessTokenOptions &option,
        const sptr<IDomainAccountCallback> &callback);
    ErrCode StartHasDomainAccount(const sptr<IDomainAccountPlugin> &plugin, const GetDomainAccountInfoOptions &options,
        const sptr<IDomainAccountCallback> &callback);
    ErrCode StartAuth(const sptr<IDomainAccountPlugin> &plugin, const DomainAccountInfo &info,
        const std::vector<uint8_t> &password, const sptr<IDomainAccountCallback> &callback, AuthMode authMode);
    sptr<IRemoteObject::DeathRecipient> GetDeathRecipient();
    ErrCode StartPluginAuth(int32_t userId, const std::vector<uint8_t> &authData, const DomainAccountInfo &domainInfo,
        const sptr<InnerDomainAuthCallback> &innerCallback, AuthMode authMode);
    ErrCode InnerAuth(int32_t userId, const std::vector<uint8_t> &authData,
        const sptr<IDomainAccountCallback> &callback, AuthMode authMode);
    ErrCode CheckUserToken(const std::vector<uint8_t> &token, bool &isValid, const DomainAccountInfo &info);
    ErrCode PluginAuth(const DomainAccountInfo &info, const std::vector<uint8_t> &password,
        uint64_t &contextId);
    ErrCode PluginGetDomainAccountInfo(const GetDomainAccountInfoOptions &options,
        DomainAccountInfo &resultParcel);
    ErrCode PluginAuthWithPopup(const DomainAccountInfo &info, DomainAuthResult &resultParcel);
    ErrCode PluginAuthToken(const DomainAccountInfo &info,  const std::vector<uint8_t> &authData,
        DomainAuthResult &resultParcel);
    ErrCode PluginGetAuthStatusInfo(const DomainAccountInfo &info, AuthStatusInfo &resultParcel);
    ErrCode PluginBindAccount(const DomainAccountInfo &info, const int32_t localId, DomainAuthResult &resultParcel);
    ErrCode PluginUnBindAccount(const DomainAccountInfo &info, DomainAuthResult &resultParcel, const int32_t localId);
    ErrCode PluginIsAccountTokenValid(const DomainAccountInfo &info, const std::vector<uint8_t> &token,
        int32_t &isValid);
    ErrCode PluginGetAccessToken(const GetAccessTokenOptions &option,
        const std::vector<uint8_t> &token, const DomainAccountInfo &info, DomainAuthResult &resultParcel);
    ErrCode PluginUpdateAccountInfo(const DomainAccountInfo &oldAccountInfo,
        const DomainAccountInfo &newAccountInfo);
    ErrCode RecoverBindDomainForUncomplete(const OsAccountInfo &osAccountInfo, const DomainAccountInfo &domainInfo);
    ErrCode BindDomainAccountWork(
        const int32_t localId, const DomainAccountInfo &domainInfo, const OsAccountInfo &info);
    ErrCode CancelAuthWork(const uint64_t &contextId);

protected:
    friend InnerDomainAuthCallback;
    bool AddToContextMap(const uint64_t contextId, const sptr<InnerDomainAuthCallback> &innerCallback);
    void EraseFromContextMap(const uint64_t contextId);
    bool FindCallbackInContextMap(const sptr<IDomainAccountCallback> &callback, uint64_t &contextId);
    std::map<uint64_t, sptr<InnerDomainAuthCallback>> authContextIdMap_;
    mutable std::recursive_mutex authContextIdMapMutex_;
    uint64_t contextIdCount_ = 0;

private:
    int32_t callingUid_ = -1;
    std::mutex mutex_;
    std::mutex libMutex_;
    sptr<IRemoteObject::DeathRecipient> deathRecipient_;
    sptr<IDomainAccountPlugin> plugin_;
    std::map<PluginMethodEnum, void*> methodMap_;
    void* libHandle_ = nullptr;
    std::map<int32_t, std::vector<uint8_t>> userTokenMap_;
};

class CheckUserTokenCallback final : public DomainAccountCallback {
public:
    void OnResult(int32_t result, Parcel &parcel) override;
    bool GetValidity();
    void WaitForCallbackResult();
    void NotifyCallbackEnd();

private:
    bool isValid_ = false;
    mutable std::mutex lock_;
    std::condition_variable condition_;
    bool threadInSleep_ = true;
};

class InnerDomainAuthCallback final: public DomainAccountCallbackStub {
public:
    InnerDomainAuthCallback(int32_t userId, const sptr<IDomainAccountCallback> &callback);
    virtual ~InnerDomainAuthCallback();
    ErrCode OnResult(int32_t errCode, const DomainAccountParcel &domainAccountParcel) override;
    void SetOpenContextIdCheck(bool isEnabled, uint64_t contextId = 0);
private:
    int32_t userId_;
    sptr<DomainAccountAuthDeathRecipient> deathRecipient_;
    bool needCheckContextId_ = false;
    std::mutex mutex_;
protected:
    friend InnerDomainAccountManager;
    sptr<IDomainAccountCallback> callback_;
};

class UpdateAccountInfoCallback final : public DomainAccountCallback {
public:
    void OnResult(int32_t result, Parcel &parcel) override;
    int32_t GetResult();
    void WaitForCallbackResult();
    DomainAccountInfo GetAccountInfo();

private:
    int32_t result_ = -1;
    mutable std::mutex lock_;
    std::condition_variable condition_;
    bool threadInSleep_ = true;
    DomainAccountInfo accountInfo_;
};

/**
 * @brief call back for sync call to domain account interface, this class would ignore parcel input.
*/
class DomainAccountCallbackSync final : public DomainAccountCallback {
public:
    void OnResult(int32_t result, Parcel &parcel) override;
    int32_t GetResult();
    void WaitForCallbackResult();

private:
    int32_t result_ = -1;
    mutable std::mutex lock_;
    std::condition_variable condition_;
    bool isCalled_ = false;
};
}  // namespace AccountSA
}  // namespace OHOS
#endif // OS_ACCOUNT_SERVICES_DOMAIN_ACCOUNT_INCLUDE_INNER_DOMAIN_ACCOUNT_MANAGER_H
