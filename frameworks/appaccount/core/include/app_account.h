/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef APP_ACCOUNT_FRAMEWORKS_APPACCOUNT_CORE_INCLUDE_APP_ACCOUNT_H
#define APP_ACCOUNT_FRAMEWORKS_APPACCOUNT_CORE_INCLUDE_APP_ACCOUNT_H

#include <map>

#include "app_account_event_listener.h"
#include "iapp_account.h"

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
    ErrCode DeleteAccount(const std::string &name);

    ErrCode GetAccountExtraInfo(const std::string &name, std::string &extraInfo);
    ErrCode SetAccountExtraInfo(const std::string &name, const std::string &extraInfo);

    ErrCode EnableAppAccess(const std::string &name, const std::string &authorizedApp);
    ErrCode DisableAppAccess(const std::string &name, const std::string &authorizedApp);

    ErrCode CheckAppAccountSyncEnable(const std::string &name, bool &syncEnable);
    ErrCode SetAppAccountSyncEnable(const std::string &name, const bool &syncEnable);

    ErrCode GetAssociatedData(const std::string &name, const std::string &key, std::string &value);
    ErrCode SetAssociatedData(const std::string &name, const std::string &key, const std::string &value);

    ErrCode GetAccountCredential(const std::string &name, const std::string &credentialType, std::string &credential);
    ErrCode SetAccountCredential(
        const std::string &name, const std::string &credentialType, const std::string &credential);

    ErrCode GetOAuthToken(const std::string &name, std::string &token);
    ErrCode SetOAuthToken(const std::string &name, const std::string &token);
    ErrCode ClearOAuthToken(const std::string &name);

    ErrCode GetAllAccounts(const std::string &owner, std::vector<AppAccountInfo> &appAccounts);
    ErrCode GetAllAccessibleAccounts(std::vector<AppAccountInfo> &appAccounts);

    ErrCode SubscribeAppAccount(const std::shared_ptr<AppAccountSubscriber> &subscriber);
    ErrCode UnsubscribeAppAccount(const std::shared_ptr<AppAccountSubscriber> &subscriber);

    ErrCode ResetAppAccountProxy();

private:
    ErrCode CheckParameters(const std::string &name, const std::string &extraInfo = "");
    ErrCode GetAppAccountProxy();
    ErrCode CreateAppAccountEventListener(
        const std::shared_ptr<AppAccountSubscriber> &subscriber, sptr<IRemoteObject> &appAccountEventListener);

    // trim from start (in place)
    static inline void ltrim(std::string &s)
    {
        s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) { return !std::isspace(ch); }));
    }

    // trim from end (in place)
    static inline void rtrim(std::string &s)
    {
        s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) { return !std::isspace(ch); }).base(), s.end());
    }

    // trim from both ends (in place)
    static inline void trim(std::string &s)
    {
        ltrim(s);
        rtrim(s);
    }

    // trim from start (copying)
    static inline std::string ltrim_copy(std::string s)
    {
        ltrim(s);
        return s;
    }

    // trim from end (copying)
    static inline std::string rtrim_copy(std::string s)
    {
        rtrim(s);
        return s;
    }

    // trim from both ends (copying)
    static inline std::string trim_copy(std::string s)
    {
        trim(s);
        return s;
    }

private:
    std::mutex mutex_;
    std::mutex eventListenersMutex_;
    sptr<IAppAccount> appAccountProxy_;
    std::map<std::shared_ptr<AppAccountSubscriber>, sptr<AppAccountEventListener>> eventListeners_;
    sptr<IRemoteObject::DeathRecipient> deathRecipient_;

    const unsigned int SUBSCRIBER_MAX_SIZE = 200;
    const unsigned int NAME_MAX_SIZE = 1024;
    const unsigned int EXTRA_INFO_MAX_SIZE = 1024;
    const unsigned int ASSOCIATED_KEY_MAX_SIZE = 1024;
    const unsigned int ASSOCIATED_VALUE_MAX_SIZE = 1024;
    const unsigned int CREDENTIAL_TYPE_MAX_SIZE = 1024;
    const unsigned int CREDENTIAL_MAX_SIZE = 1024;
    const unsigned int TOKEN_MAX_SIZE = 1024;
    const unsigned int OWNER_MAX_SIZE = 1024;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // APP_ACCOUNT_FRAMEWORKS_APPACCOUNT_CORE_INCLUDE_APP_ACCOUNT_H
