/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "domain_account_common.h"
#include "domain_account_plugin_death_recipient.h"
#include "domain_account_plugin_proxy.h"
#include "domain_account_callback.h"
#include "domain_account_callback_stub.h"
#include "domain_plugin.h"
#include "int_wrapper.h"
#include "bool_wrapper.h"
#include "os_account_info.h"
#include "want.h"

namespace OHOS {
namespace AccountSA {
class InnerDomainAccountManager {
public:
    static InnerDomainAccountManager &GetInstance();
    ErrCode RegisterPlugin(const sptr<IDomainAccountPlugin> &plugin);
    void UnregisterPlugin();
    ErrCode Auth(const DomainAccountInfo &info, const std::vector<uint8_t> &password,
        const sptr<IDomainAccountCallback> &callback);
    ErrCode AuthUser(int32_t userId, const std::vector<uint8_t> &password,
        const sptr<IDomainAccountCallback> &callback);
    ErrCode AuthWithPopup(int32_t userId, const sptr<IDomainAccountCallback> &callback);
    ErrCode AuthWithToken(int32_t userId, const std::vector<uint8_t> &token);
    ErrCode GetAuthStatusInfo(const DomainAccountInfo &info, const std::shared_ptr<DomainAccountCallback> &callback);
    ErrCode HasDomainAccount(const DomainAccountInfo &info, const sptr<IDomainAccountCallback> &callback);
    ErrCode UpdateAccountToken(const DomainAccountInfo &info, const std::vector<uint8_t> &token);
    ErrCode IsAuthenticationExpired(const DomainAccountInfo &info, bool &isExpired);
    ErrCode SetAccountPolicy(const DomainAccountPolicy &policy);
    ErrCode GetAccessToken(const DomainAccountInfo &info, const AAFwk::WantParams &parameters,
        const sptr<IDomainAccountCallback> &callback);
    ErrCode GetDomainAccountInfo(const DomainAccountInfo &info, const sptr<IDomainAccountCallback> &callback);
    ErrCode OnAccountBound(const DomainAccountInfo &info, const int32_t localId,
        const std::shared_ptr<DomainAccountCallback> &callback);
    ErrCode IsAccountTokenValid(const AccountSA::DomainAccountInfo &info, const std::vector<uint8_t> &token,
        const std::shared_ptr<DomainAccountCallback> &callback);
    ErrCode OnAccountUnBound(const DomainAccountInfo &info, const std::shared_ptr<DomainAccountCallback> &callback);
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
    ErrCode GetAccountServerConfig(const DomainAccountInfo &info, DomainServerConfig &config);
    void LoaderLib(const std::string &path, const std::string &libName);
    void CloseLib();
    ErrCode UpdateAccountInfo(const DomainAccountInfo &oldAccountInfo, const DomainAccountInfo &newAccountInfo);

private:
    InnerDomainAccountManager();
    ~InnerDomainAccountManager();
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
    ErrCode InnerAuth(int32_t userId, const std::vector<uint8_t> &authData,
        const sptr<IDomainAccountCallback> &callback, AuthMode authMode);
    ErrCode CheckUserToken(const std::vector<uint8_t> &token, bool &isValid, int32_t userId);
    ErrCode PluginAuth(const DomainAccountInfo &info, const std::vector<uint8_t> &password,
        DomainAuthResult &resultParcel);
    ErrCode PluginGetDomainAccountInfo(const GetDomainAccountInfoOptions &options,
        DomainAccountInfo &resultParcel);
    ErrCode PluginAuthWithPopup(const DomainAccountInfo &info, DomainAuthResult &resultParcel);
    ErrCode PluginAuthToken(const DomainAccountInfo &info,  const std::vector<uint8_t> &authData,
        DomainAuthResult &resultParcel);
    ErrCode PluginGetAuthStatusInfo(const DomainAccountInfo &info, AuthStatusInfo &resultParcel);
    ErrCode PluginBindAccount(const DomainAccountInfo &info, const int32_t localId, DomainAuthResult &resultParcel);
    ErrCode PluginUnBindAccount(const DomainAccountInfo &info, DomainAuthResult &resultParcel);
    ErrCode PluginIsAccountTokenValid(const DomainAccountInfo &info, const std::vector<uint8_t> &token,
        int32_t &isValid);
    ErrCode PluginGetAccessToken(const GetAccessTokenOptions &option,
        const std::vector<uint8_t> &token, const DomainAccountInfo &info, DomainAuthResult &resultParcel);
    ErrCode PluginUpdateAccountInfo(const DomainAccountInfo &oldAccountInfo,
        const DomainAccountInfo &newAccountInfo);

private:
    int32_t callingUid_ = -1;
    std::mutex mutex_;
    std::mutex libMutex_;
    sptr<IRemoteObject::DeathRecipient> deathRecipient_;
    sptr<IDomainAccountPlugin> plugin_;
    std::map<PluginMethodEnum, void*> methodMap;
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
    void OnResult(const int32_t errCode, Parcel &parcel) override;

private:
    int32_t userId_;
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
}  // namespace AccountSA
}  // namespace OHOS
#endif // OS_ACCOUNT_SERVICES_DOMAIN_ACCOUNT_INCLUDE_INNER_DOMAIN_ACCOUNT_MANAGER_H
