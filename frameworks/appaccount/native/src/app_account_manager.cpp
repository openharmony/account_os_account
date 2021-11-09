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

#include "account_log_wrapper.h"
#include "app_account.h"
#include "singleton.h"

#include "app_account_manager.h"

namespace OHOS {
namespace AccountSA {
ErrCode AppAccountManager::AddAccount(const std::string &name, const std::string &extraInfo)
{
    ACCOUNT_LOGI("enter");

    return DelayedSingleton<AppAccount>::GetInstance()->AddAccount(name, extraInfo);
}

ErrCode AppAccountManager::DeleteAccount(const std::string &name)
{
    ACCOUNT_LOGI("enter");

    return DelayedSingleton<AppAccount>::GetInstance()->DeleteAccount(name);
}

ErrCode AppAccountManager::GetAccountExtraInfo(const std::string &name, std::string &extraInfo)
{
    ACCOUNT_LOGI("enter");

    return DelayedSingleton<AppAccount>::GetInstance()->GetAccountExtraInfo(name, extraInfo);
}

ErrCode AppAccountManager::SetAccountExtraInfo(const std::string &name, const std::string &extraInfo)
{
    ACCOUNT_LOGI("enter");

    return DelayedSingleton<AppAccount>::GetInstance()->SetAccountExtraInfo(name, extraInfo);
}

ErrCode AppAccountManager::EnableAppAccess(const std::string &name, const std::string &authorizedApp)
{
    ACCOUNT_LOGI("enter");

    return DelayedSingleton<AppAccount>::GetInstance()->EnableAppAccess(name, authorizedApp);
}

ErrCode AppAccountManager::DisableAppAccess(const std::string &name, const std::string &authorizedApp)
{
    ACCOUNT_LOGI("enter");

    return DelayedSingleton<AppAccount>::GetInstance()->DisableAppAccess(name, authorizedApp);
}

ErrCode AppAccountManager::CheckAppAccountSyncEnable(const std::string &name, bool &syncEnable)
{
    ACCOUNT_LOGI("enter");

    return DelayedSingleton<AppAccount>::GetInstance()->CheckAppAccountSyncEnable(name, syncEnable);
}

ErrCode AppAccountManager::SetAppAccountSyncEnable(const std::string &name, const bool &syncEnable)
{
    ACCOUNT_LOGI("enter");

    return DelayedSingleton<AppAccount>::GetInstance()->SetAppAccountSyncEnable(name, syncEnable);
}

ErrCode AppAccountManager::GetAssociatedData(const std::string &name, const std::string &key, std::string &value)
{
    ACCOUNT_LOGI("enter");

    return DelayedSingleton<AppAccount>::GetInstance()->GetAssociatedData(name, key, value);
}

ErrCode AppAccountManager::SetAssociatedData(const std::string &name, const std::string &key, const std::string &value)
{
    ACCOUNT_LOGI("enter");

    return DelayedSingleton<AppAccount>::GetInstance()->SetAssociatedData(name, key, value);
}

ErrCode AppAccountManager::GetAccountCredential(
    const std::string &name, const std::string &credentialType, std::string &credential)
{
    ACCOUNT_LOGI("enter");

    return DelayedSingleton<AppAccount>::GetInstance()->GetAccountCredential(name, credentialType, credential);
}

ErrCode AppAccountManager::SetAccountCredential(
    const std::string &name, const std::string &credentialType, const std::string &credential)
{
    ACCOUNT_LOGI("enter");

    return DelayedSingleton<AppAccount>::GetInstance()->SetAccountCredential(name, credentialType, credential);
}

ErrCode AppAccountManager::GetOAuthToken(const std::string &name, std::string &token)
{
    ACCOUNT_LOGI("enter");

    return DelayedSingleton<AppAccount>::GetInstance()->GetOAuthToken(name, token);
}

ErrCode AppAccountManager::SetOAuthToken(const std::string &name, const std::string &token)
{
    ACCOUNT_LOGI("enter");

    return DelayedSingleton<AppAccount>::GetInstance()->SetOAuthToken(name, token);
}

ErrCode AppAccountManager::ClearOAuthToken(const std::string &name)
{
    ACCOUNT_LOGI("enter");

    return DelayedSingleton<AppAccount>::GetInstance()->ClearOAuthToken(name);
}

ErrCode AppAccountManager::GetAllAccounts(const std::string &owner, std::vector<AppAccountInfo> &appAccounts)
{
    ACCOUNT_LOGI("enter");

    return DelayedSingleton<AppAccount>::GetInstance()->GetAllAccounts(owner, appAccounts);
}

ErrCode AppAccountManager::GetAllAccessibleAccounts(std::vector<AppAccountInfo> &appAccounts)
{
    ACCOUNT_LOGI("enter");

    return DelayedSingleton<AppAccount>::GetInstance()->GetAllAccessibleAccounts(appAccounts);
}

ErrCode AppAccountManager::SubscribeAppAccount(const std::shared_ptr<AppAccountSubscriber> &subscriber)
{
    ACCOUNT_LOGI("enter");

    return DelayedSingleton<AppAccount>::GetInstance()->SubscribeAppAccount(subscriber);
}

ErrCode AppAccountManager::UnsubscribeAppAccount(const std::shared_ptr<AppAccountSubscriber> &subscriber)
{
    ACCOUNT_LOGI("enter");

    return DelayedSingleton<AppAccount>::GetInstance()->UnsubscribeAppAccount(subscriber);
}
}  // namespace AccountSA
}  // namespace OHOS
