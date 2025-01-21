/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#ifndef APPACCOUNT_IMPL_H
#define APPACCOUNT_IMPL_H

#include <map>
#include <mutex>
#include <string>

#include "app_account_subscriber.h"
#include "appaccount_common.h"
#include "appaccount_defination.h"
#include "appaccount_ffi.h"
#include "appaccount_parameter_parse.h"

namespace OHOS::AccountSA {
class CJAppAccountImpl : public OHOS::FFI::FFIData {
    DECL_TYPE(CJAppAccountImpl, OHOS::FFI::FFIData)
public:
    CJAppAccountImpl() = default;
    ~CJAppAccountImpl() = default;
    std::mutex mutex_;
    std::vector<AsyncContextForSubscribe *> g_appAccountSubscribes;

    int32_t createAccount(std::string name, CCreateAccountOptions cOptions);
    int32_t removeAccount(std::string name);
    int32_t setAppAccess(std::string name, std::string bundleName, bool isAccessible);
    RetDataBool checkAppAccess(std::string name, std::string bundleName);
    RetDataBool checkDataSyncEnabled(std::string name);
    int32_t setCredential(std::string name, std::string credentialType, std::string credential);
    int32_t setDataSyncEnabled(std::string name, bool isEnabled);
    int32_t setCustomData(std::string name, std::string key, std::string value);
    ErrCArrAppAccountInfo getAccountsByOwner(std::string owner);
    RetDataCString getCredential(std::string name, std::string credentialType);
    RetDataCString getCustomData(std::string name, std::string key);
    RetDataCString getAuthToken(std::string name, std::string owner, std::string authType);
    int32_t setAuthToken(std::string name, std::string authType, std::string token);
    int32_t deleteAuthToken(std::string name, std::string owner, std::string authType, std::string token);
    int32_t setAuthTokenVisibility(std::string name, std::string authType, std::string bundleName, bool isVisible);
    RetDataBool checkAuthTokenVisibility(std::string name, std::string authType, std::string bundleName);
    ErrCArrAuthTokenInfo getAllAuthTokens(std::string name, std::string owner);
    RetDataCArrString getAuthList(std::string name, std::string authType);
    ErrCAuthenticatorInfo queryAuthenticatorInfo(std::string owner);
    int32_t deleteCredential(std::string name, std::string credentialType);
    ErrCArrAppAccountInfo getAllAccounts();
    int32_t on(std::string type, CArrString owners, void (*callback)(CArrAppAccountInfo cArrAppAccountInfo));
    int32_t off(std::string type, void (*callback)(CArrAppAccountInfo cArrAppAccountInfo));
    int32_t checkAccountLabels(
        std::string name, std::string owner, CArrString labels, const std::function<void(RetDataBool)> &callbackRef);
    int32_t selectAccountByOptions(
        CSelectAccountsOptions cOptions, const std::function<void(ErrCArrAppAccountInfo)> &callbackRef);
    int32_t verifyCredential(
        std::string name, std::string owner, CAuthCallback callbackId, CVerifyCredentialOptions cOptions);
    int32_t setAuthenticatorProperties(std::string owner, CAuthCallback callbackId, CSetPropertiesOptions cOptions);

private:
    bool ParseContextForCheckAccountLabels(std::string name, std::string owner, CArrString labels,
        const std::function<void(RetDataBool)> &callbackRef, std::unique_ptr<CheckAccountLabelsContext> &context);
    bool ParseContextForSelectAccount(
        CSelectAccountsOptions cOptions,
        const std::function<void(ErrCArrAppAccountInfo)> &callbackRef,
        std::unique_ptr<SelectAccountsContext> &context);
    void ParseContextForVerifyCredential(CAuthCallback callbackId, CVerifyCredentialOptions cOptions,
        JSAuthCallback &callback, VerifyCredentialOptions &options);
    void ParseContextForSetAuthenticatorProperties(CAuthCallback callbackId, CSetPropertiesOptions cOptions,
        JSAuthCallback &callback, SetPropertiesOptions &options);

    void GetSubscriberByUnsubscribe(std::vector<std::shared_ptr<SubscribePtr>> &subscribers);

    std::map<std::string, std::string> ConvertCArr2Map(const CHashStrStrArr &cHeaders);
    void Convert2CreateAccountOptions(CCreateAccountOptions &in, CreateAccountOptions &out);
    std::vector<AppAccountInfo> Convert2VecAppAccountInfo(const CArrAppAccountInfo &in);
    CArrAppAccountInfo Convert2CArrAppAccountInfo(const std::vector<AppAccountInfo> &in);
    CArrAppAccountInfo Convert2CArrAppAccountInfo(
        const std::vector<std::string> &names, const std::vector<std::string> &owners);
    CArrAuthTokenInfo Convert2CArrAuthTokenInfo(const std::vector<OAuthTokenInfo> &in);
    void clearCharPointer(char **ptr, int count);
    CArrString ConvertSet2CArrString(std::set<std::string> &in);
    CArrString ConvertVec2CArrString(std::vector<std::string> &in);
    std::vector<std::string> Convert2VecString(CArrString &in);
    CAuthenticatorInfo Convert2CAuthenticatorInfo(AuthenticatorInfo &in);
    std::vector<std::pair<std::string, std::string>> Convert2VecAppAccountInfo(CArrAppAccountInfo &in);
    void Convert2SelectAccountsOptions(CSelectAccountsOptions &in, SelectAccountsOptions &out);
    CAuthResult Convert2CAuthResult(std::string name, std::string owner, std::string authType, std::string token);
    bool IsSameFunction(
        const std::function<void(CArrAppAccountInfo)> *f1, const std::function<void(CArrAppAccountInfo)> *f2);
    bool IsExitSubscibe(AsyncContextForSubscribe *context);
};
} // namespace::OHOS::AccountSA
#endif