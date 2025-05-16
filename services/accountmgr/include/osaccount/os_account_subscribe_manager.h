/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include <deque>
#include <map>
#include <memory>
#include <set>

#include "ios_account_event.h"
#include "ios_account_subscribe.h"
#include "os_account_state_parcel.h"
#include "singleton.h"

namespace OHOS {
namespace AccountSA {
struct SwitchSubcribeWork {
    SwitchSubcribeWork() = default;
    SwitchSubcribeWork(const sptr<IOsAccountEvent> &eventProxy, const OsAccountStateParcel &stateParcel);
    ~SwitchSubcribeWork() = default;
    sptr<IOsAccountEvent> eventProxy_ = nullptr;
    OsAccountStateParcel stateParcel_;
};

class SwitchSubscribeInfo : public std::enable_shared_from_this<SwitchSubscribeInfo> {
public:
    SwitchSubscribeInfo() = default;
    SwitchSubscribeInfo(OS_ACCOUNT_SUBSCRIBE_TYPE);
    ~SwitchSubscribeInfo();
    void AddSubscribeInfo();
    bool SubSubscribeInfo();
    bool IsEmpty();
    bool ProductTask(const sptr<IOsAccountEvent> &eventProxy, OsAccountStateParcel &stateParcel);

public:
    std::mutex mutex_;
    std::deque<std::shared_ptr<SwitchSubcribeWork>> workDeque_;
    std::unique_ptr<std::thread> workThread_;
private:
    uint8_t count_ = 0;
};

class OsAccountSubscribeManager : public IOsAccountSubscribe {
public:
    static OsAccountSubscribeManager &GetInstance();
    ErrCode SubscribeOsAccount(const std::shared_ptr<OsAccountSubscribeInfo> &subscribeInfoPtr,
        const sptr<IRemoteObject> &eventListener) override;
    ErrCode UnsubscribeOsAccount(const sptr<IRemoteObject> &eventListener) override;
    const std::shared_ptr<OsAccountSubscribeInfo> GetSubscribeRecordInfo(
        const sptr<IRemoteObject> &eventListener) override;
    ErrCode Publish(int32_t fromId, OsAccountState state, int32_t toId) override;

private:
    OsAccountSubscribeManager();
    ~OsAccountSubscribeManager() = default;
    bool OnStateChanged(const sptr<IOsAccountEvent> &eventProxy, OsAccountStateParcel &stateParcel, int32_t targetUid);
    // Compatible with historical versions
    bool OnStateChangedV0(const sptr<IOsAccountEvent> &eventProxy, OsAccountState state, int32_t fromId, int32_t toId,
        int32_t targetUid);
    bool OnAccountsChanged(const sptr<IOsAccountEvent> &eventProxy,
        OsAccountState state, int32_t id, int32_t targetUid);
    DISALLOW_COPY_AND_MOVE(OsAccountSubscribeManager);
    ErrCode RemoveSubscribeRecord(const sptr<IRemoteObject> &eventListener);

private:
    std::mutex mutex_;
    sptr<IRemoteObject::DeathRecipient> subscribeDeathRecipient_;
    std::mutex subscribeRecordMutex_;
    std::set<OsSubscribeRecordPtr> subscribeRecords_;
    std::map<int32_t, std::shared_ptr<SwitchSubscribeInfo>> switchRecordMap_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APP_ACCOUNT_SUBSCRIBE_MANAGER_H
