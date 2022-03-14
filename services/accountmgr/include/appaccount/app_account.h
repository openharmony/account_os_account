/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_H

#include <map>

#include "app_account_event_listener.h"
#include "iapp_account.h"
#include "iapp_account_authenticator_callback.h"

namespace OHOS {
namespace AccountSA {
class AppAccount {
public:
    enum SubscribeState {
        ALREADY_SUBSCRIBED = 0,
        INITIAL_SUBSCRIPTION,
        SUBSCRIBE_FAILD,
    };

    ErrCode AddAccount(const std::string &name, const std::string &extraInfo);
    ErrCode AddAccountImplicitly(const std::string &owner, const std::string &authType,
        const AAFwk::Want &options, const sptr<IAppAccountAuthenticatorCallback> &callback);
    ErrCode DeleteAccount(const std::string &name);

    ErrCode GetAccountExtraInfo(const std::string &name, std::string &extraInfo);
    ErrCode SetAccountExtraInfo(const std::string &name, const std::string &extraInfo);

    ErrCode EnableAppAccess(const std::string &name, const std::string &bundleName);
    ErrCode DisableAppAccess(const std::string &name, const std::string &bundleName);

    ErrCode CheckAppAccountSyncEnable(const std::string &name, bool &syncEnable);
    ErrCode SetAppAccountSyncEnable(const std::string &name, const bool &syncEnable);

    ErrCode GetAssociatedData(const std::string &name, const std::string &key, std::string &value);
    ErrCode SetAssociatedData(const std::string &name, const std::string &key, const std::string &value);

    ErrCode GetAccountCredential(const std::string &name, const std::string &credentialType, std::string &credential);
    ErrCode SetAccountCredential(
        const std::string &name, const std::string &credentialType, const std::string &credential);

    ErrCode Authenticate(const std::string &name, const std::string &owner, const std::string &authType,
        const AAFwk::Want &options, const sptr<IAppAccountAuthenticatorCallback> &callback);
    ErrCode GetOAuthToken(
        const std::string &name, const std::string &owner, const std::string &authType, std::string &token);
    ErrCode SetOAuthToken(const std::string &name, const std::string &authType, const std::string &token);
    ErrCode DeleteOAuthToken(
        const std::string &name, const std::string &owner, const std::string &authType, const std::string &token);
    ErrCode SetOAuthTokenVisibility(
        const std::string &name, const std::string &authType, const std::string &bundleName, bool isVisible);
    ErrCode CheckOAuthTokenVisibility(
        const std::string &name, const std::string &authType, const std::string &bundleName, bool &isVisible);
    ErrCode GetAuthenticatorInfo(const std::string &owner, AuthenticatorInfo &info);
    ErrCode GetAllOAuthTokens(
        const std::string &name, const std::string &owner, std::vector<OAuthTokenInfo> &tokenInfos);
    ErrCode GetOAuthList(
        const std::string &name, const std::string &authType, std::set<std::string> &oauthList);
    ErrCode GetAuthenticatorCallback(const std::string &sessionId, sptr<IRemoteObject> &callback);

    ErrCode GetAllAccounts(const std::string &owner, std::vector<AppAccountInfo> &appAccounts);
    ErrCode GetAllAccessibleAccounts(std::vector<AppAccountInfo> &appAccounts);

    ErrCode SubscribeAppAccount(const std::shared_ptr<AppAccountSubscriber> &subscriber);
    ErrCode UnsubscribeAppAccount(const std::shared_ptr<AppAccountSubscriber> &subscriber);

    ErrCode ResetAppAccountProxy();

private:
    ErrCode CheckParameters(const std::string &name, const std::string &extraInfo = "");
    ErrCode CheckSpecialCharacters(const std::string &name);

    ErrCode GetAppAccountProxy();
    ErrCode CreateAppAccountEventListener(
        const std::shared_ptr<AppAccountSubscriber> &subscriber, sptr<IRemoteObject> &appAccountEventListener);

private:
    std::mutex mutex_;
    std::mutex eventListenersMutex_;
    sptr<IAppAccount> appAccountProxy_;
    std::map<std::shared_ptr<AppAccountSubscriber>, sptr<AppAccountEventListener>> eventListeners_;
    sptr<IRemoteObject::DeathRecipient> deathRecipient_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_H
