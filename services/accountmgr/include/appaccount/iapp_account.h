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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_IAPP_ACCOUNT_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_IAPP_ACCOUNT_H

#include "app_account_subscribe_info.h"
#include "app_account_info.h"
#include "iremote_broker.h"
#include "iremote_object.h"

namespace OHOS {
namespace AccountSA {
class IAppAccount : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.accountfwk.IAppAccount");

    virtual ErrCode AddAccount(const std::string &name, const std::string &extraInfo) = 0;
    virtual ErrCode DeleteAccount(const std::string &name) = 0;

    virtual ErrCode GetAccountExtraInfo(const std::string &name, std::string &extraInfo) = 0;
    virtual ErrCode SetAccountExtraInfo(const std::string &name, const std::string &extraInfo) = 0;

    virtual ErrCode EnableAppAccess(const std::string &name, const std::string &authorizedApp) = 0;
    virtual ErrCode DisableAppAccess(const std::string &name, const std::string &authorizedApp) = 0;

    virtual ErrCode CheckAppAccountSyncEnable(const std::string &name, bool &syncEnable) = 0;
    virtual ErrCode SetAppAccountSyncEnable(const std::string &name, const bool &syncEnable) = 0;

    virtual ErrCode GetAssociatedData(const std::string &name, const std::string &key, std::string &value) = 0;
    virtual ErrCode SetAssociatedData(const std::string &name, const std::string &key, const std::string &value) = 0;

    virtual ErrCode GetAccountCredential(
        const std::string &name, const std::string &credentialType, std::string &credential) = 0;
    virtual ErrCode SetAccountCredential(
        const std::string &name, const std::string &credentialType, const std::string &credential) = 0;

    virtual ErrCode GetOAuthToken(const std::string &name, std::string &token) = 0;
    virtual ErrCode SetOAuthToken(const std::string &name, const std::string &token) = 0;
    virtual ErrCode ClearOAuthToken(const std::string &name) = 0;

    virtual ErrCode GetAllAccounts(const std::string &owner, std::vector<AppAccountInfo> &appAccounts) = 0;
    virtual ErrCode GetAllAccessibleAccounts(std::vector<AppAccountInfo> &appAccounts) = 0;

    virtual ErrCode SubscribeAppAccount(
        const AppAccountSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &eventListener) = 0;
    virtual ErrCode UnsubscribeAppAccount(const sptr<IRemoteObject> &eventListener) = 0;

    enum class Message {
        ADD_ACCOUNT = 0,
        DELETE_ACCOUNT,
        GET_ACCOUNT_EXTRA_INFO,
        SET_ACCOUNT_EXTRA_INFO,
        ENABLE_APP_ACCESS,
        DISABLE_APP_ACCESS,
        CHECK_APP_ACCOUNT_SYNC_ENABLE,
        SET_APP_ACCOUNT_SYNC_ENABLE,
        GET_ASSOCIATED_DATA,
        SET_ASSOCIATED_DATA,
        GET_ACCOUNT_CREDENTIAL,
        SET_ACCOUNT_CREDENTIAL,
        GET_OAUTH_TOKEN,
        SET_OAUTH_TOKEN,
        CLEAR_OAUTH_TOKEN,
        GET_ALL_ACCOUNTS,
        GET_ALL_ACCESSIBLE_ACCOUNTS,
        SUBSCRIBE_ACCOUNT,
        UNSUBSCRIBE_ACCOUNT,
    };
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_IAPP_ACCOUNT_H
