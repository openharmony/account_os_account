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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APP_ACCOUNT_SUBSCRIBE_MANAGER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APP_ACCOUNT_SUBSCRIBE_MANAGER_H

#include <map>
#include <set>

#include "iapp_account_subscribe.h"
#include "singleton.h"

namespace OHOS {
namespace AccountSA {
class AppAccountSubscribeManager : public IAppAccountSubscribe, public DelayedSingleton<AppAccountSubscribeManager> {
public:
    AppAccountSubscribeManager();
    virtual ~AppAccountSubscribeManager();

    ErrCode SubscribeAppAccount(const std::shared_ptr<AppAccountSubscribeInfo> &subscribeInfoPtr,
        const sptr<IRemoteObject> &eventListener, const std::string &bundleName) override;
    ErrCode UnsubscribeAppAccount(const sptr<IRemoteObject> &eventListener) override;

    std::vector<AppAccountSubscribeRecordPtr> GetSubscribeRecords(const std::string &owner);

private:
    std::shared_ptr<AppAccountDataStorage> GetDataStorage(
        const bool &autoSync = false, const int32_t uid = AppExecFwk::Constants::INVALID_UID) override;
    ErrCode GetStoreId(std::string &storeId, int32_t uid = AppExecFwk::Constants::INVALID_UID) override;
    ErrCode GetEventHandler(void) override;

    bool PublishAccount(AppAccountInfo &appAccountInfo, const std::string &bundleName) override;
    ErrCode OnAccountsChanged(const std::shared_ptr<AppAccountEventRecord> &record) override;

    ErrCode CheckAppAccess(
        const std::shared_ptr<AppAccountSubscribeInfo> &subscribeInfoPtr, const std::string &bundleName);

    ErrCode InsertSubscribeRecord(
        const std::vector<std::string> &owners, const AppAccountSubscribeRecordPtr &subscribeRecordPtr);
    ErrCode RemoveSubscribeRecord(const sptr<IRemoteObject> &eventListener);

private:
    std::shared_ptr<EventHandler> handler_;
    std::mutex mutex_;
    sptr<IRemoteObject::DeathRecipient> subscribeDeathRecipient_;
    std::mutex subscribeRecordMutex_;
    std::map<std::string, std::multiset<AppAccountSubscribeRecordPtr>> ownerSubscribeRecords_;
    std::vector<AppAccountSubscribeRecordPtr> subscribeRecords_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APP_ACCOUNT_SUBSCRIBE_MANAGER_H
