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

#include "ios_account_subscribe.h"
#include "singleton.h"

namespace OHOS {
namespace AccountSA {
class OsAccountSubscribeManager : public IOsAccountSubscribe, public DelayedSingleton<OsAccountSubscribeManager> {
public:
    OsAccountSubscribeManager();
    virtual ~OsAccountSubscribeManager();

    virtual ErrCode SubscribeOsAccount(const std::shared_ptr<OsAccountSubscribeInfo> &subscribeInfoPtr,
        const sptr<IRemoteObject> &eventListener) override;
    virtual ErrCode UnsubscribeOsAccount(const sptr<IRemoteObject> &eventListener) override;
    virtual ErrCode PublicActivatedOsAccount(const int id) override;
    virtual ErrCode PublicActivatingOsAccount(const int id) override;
    virtual ErrCode GetEventHandler(void) override;
    bool OnAccountsChanged(const OsSubscribeRecordPtr &osSubscribeRecordPtr, const int id);

private:
    ErrCode InsertSubscribeRecord(const OsSubscribeRecordPtr &subscribeRecordPtr);
    ErrCode RemoveSubscribeRecord(const sptr<IRemoteObject> &eventListener);

private:
    std::mutex mutex_;
    sptr<IRemoteObject::DeathRecipient> subscribeDeathRecipient_;
    std::mutex subscribeRecordMutex_;
    std::vector<OsSubscribeRecordPtr> subscribeRecords_;
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APP_ACCOUNT_SUBSCRIBE_MANAGER_H
