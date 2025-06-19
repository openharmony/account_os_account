/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "subscribeosaccountstub_fuzzer.h"
#include <string>
#include <thread>
#include <vector>

#include "fuzz_data.h"
#include "ios_account.h"
#include "os_account_event_listener.h"
#include "os_account_manager_service.h"
#include "os_account_subscriber.h"
#include "os_account_subscribe_manager.h"

using namespace std;
using namespace OHOS::AccountSA;

class TestOsAccountSubscriber : public OsAccountSubscriber {
public:
    void OnAccountsChanged(const int& id) {}
};

class TestOsAccountEventListener : public OsAccountEventListener {
public:
    TestOsAccountEventListener() = default;
    virtual ~TestOsAccountEventListener() = default;
    
    OHOS::ErrCode OnAccountsChanged(int32_t id) override
    {
        return OHOS::ERR_OK;
    }
    OHOS::ErrCode OnStateChanged(const OsAccountStateParcel &parcel) override
    {
        return OHOS::ERR_OK;
    }
};

namespace OHOS {
const int CONSTANTS_STATE_MAX = 13;
const int CONSTANTS_SUBSCRIBE_TYPE_MAX = 13;
constexpr uint32_t MAX_STATE_PUBLISH_COUNT = 5;
constexpr uint32_t MIN_STATE_PUBLISH_COUNT = 1;
const std::u16string IOS_ACCOUNT_DESCRIPTOR = u"ohos.accountfwk.IOsAccount";
bool SubscribeOsAccountStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    MessageParcel datas;
    datas.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR);
    FuzzData fuzzData(data, size);
    
    OsAccountSubscribeInfo subscribeInfo;
    subscribeInfo.SetName(fuzzData.GenerateString());
    
    int32_t subscribeTypeValue = (fuzzData.GetData<int32_t>() % CONSTANTS_SUBSCRIBE_TYPE_MAX) - 1;
    OS_ACCOUNT_SUBSCRIBE_TYPE testType = static_cast<OS_ACCOUNT_SUBSCRIBE_TYPE>(subscribeTypeValue);
    subscribeInfo.SetOsAccountSubscribeType(testType);

    if (!datas.WriteParcelable(&subscribeInfo)) {
        return false;
    }

    sptr<OsAccountEventListener> listener = new (std::nothrow) OsAccountEventListener();
    if (listener == nullptr) {
        return false;
    }
    sptr<IRemoteObject> osAccountEventListener = listener->AsObject();

    if (!datas.WriteRemoteObject(osAccountEventListener)) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;

    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();

    osAccountManagerService_ ->OnRemoteRequest(
        static_cast<int32_t>(IOsAccountIpcCode::COMMAND_SUBSCRIBE_OS_ACCOUNT), datas, reply, option);

    return true;
}

bool OsAccountSubscribeManagerFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzData fuzzData(data, size);
    auto &manager = OsAccountSubscribeManager::GetInstance();

    auto subscribeInfo = std::make_shared<OsAccountSubscribeInfo>();
    subscribeInfo->SetName(fuzzData.GenerateString());
    
    int32_t subscribeTypeValue = (fuzzData.GetData<int32_t>() % CONSTANTS_SUBSCRIBE_TYPE_MAX) - 1;
    OS_ACCOUNT_SUBSCRIBE_TYPE testType = static_cast<OS_ACCOUNT_SUBSCRIBE_TYPE>(subscribeTypeValue);
    subscribeInfo->SetOsAccountSubscribeType(testType);

    sptr<OsAccountEventListener> listener = new (std::nothrow) TestOsAccountEventListener();
    if (listener == nullptr) {
        return false;
    }
    sptr<IRemoteObject> eventListener = listener->AsObject();
    if (eventListener == nullptr) {
        return false;
    }

    manager.SubscribeOsAccount(subscribeInfo, eventListener);

    auto recordInfo = manager.GetSubscribeRecordInfo(eventListener);

    int32_t fromId = fuzzData.GetData<int32_t>();
    int32_t toId = fuzzData.GetData<int32_t>();
    
    uint32_t stateCount = (fuzzData.GetData<uint32_t>() % MAX_STATE_PUBLISH_COUNT) + MIN_STATE_PUBLISH_COUNT;
    
    for (uint32_t i = 0; i < stateCount; i++) {
        int32_t stateValue = (fuzzData.GetData<int32_t>() % CONSTANTS_STATE_MAX) - 1;
        OsAccountState randomState = static_cast<OsAccountState>(stateValue);
        
        int32_t randomFromId = fuzzData.GetData<int32_t>();
        int32_t randomToId = fuzzData.GetData<int32_t>();
        
        manager.Publish(randomFromId, randomState, randomToId);
    }
    
    if (fuzzData.GetData<bool>()) {
        manager.Publish(fromId, OsAccountState::SWITCHING, toId);
        manager.Publish(toId, OsAccountState::SWITCHED, fromId);
    }
    
    if (fuzzData.GetData<bool>()) {
        manager.Publish(fromId, OsAccountState::STOPPING, toId);
        manager.Publish(toId, OsAccountState::STOPPED, fromId);
    }
    
    manager.UnsubscribeOsAccount(eventListener);
    return true;
}

bool SetupOsAccountSubscription(const uint8_t *data, size_t size,
    OsAccountSubscribeManager &manager, OS_ACCOUNT_SUBSCRIBE_TYPE &selectedType, sptr<IRemoteObject> &eventListener)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzData fuzzData(data, size);

    std::vector<OS_ACCOUNT_SUBSCRIBE_TYPE> subscribeTypes = {
        OS_ACCOUNT_SUBSCRIBE_TYPE::INVALID_TYPE,
        OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATED,
        OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATING,
        OS_ACCOUNT_SUBSCRIBE_TYPE::UNLOCKED,
        OS_ACCOUNT_SUBSCRIBE_TYPE::CREATED,
        OS_ACCOUNT_SUBSCRIBE_TYPE::REMOVED,
        OS_ACCOUNT_SUBSCRIBE_TYPE::STOPPING,
        OS_ACCOUNT_SUBSCRIBE_TYPE::STOPPED,
        OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHING,
        OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHED,
        OS_ACCOUNT_SUBSCRIBE_TYPE::CREATING,
        OS_ACCOUNT_SUBSCRIBE_TYPE::LOCKING,
        OS_ACCOUNT_SUBSCRIBE_TYPE::LOCKED
    };

    selectedType = subscribeTypes[fuzzData.GetData<uint32_t>() % subscribeTypes.size()];

    auto subscribeInfo = std::make_shared<OsAccountSubscribeInfo>();
    subscribeInfo->SetName(fuzzData.GenerateString());
    subscribeInfo->SetOsAccountSubscribeType(selectedType);

    sptr<OsAccountEventListener> listener = new (std::nothrow) TestOsAccountEventListener();
    if (listener == nullptr) {
        return false;
    }
    eventListener = listener->AsObject();

    manager.SubscribeOsAccount(subscribeInfo, eventListener);
    return true;
}

static const std::map<OS_ACCOUNT_SUBSCRIBE_TYPE, OsAccountState> SUBSCRIBE_TO_STATE_MAP = {
    {OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATED, OsAccountState::ACTIVATED},
    {OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATING, OsAccountState::ACTIVATING},
    {OS_ACCOUNT_SUBSCRIBE_TYPE::UNLOCKED, OsAccountState::UNLOCKED},
    {OS_ACCOUNT_SUBSCRIBE_TYPE::CREATED, OsAccountState::CREATED},
    {OS_ACCOUNT_SUBSCRIBE_TYPE::REMOVED, OsAccountState::REMOVED},
    {OS_ACCOUNT_SUBSCRIBE_TYPE::STOPPING, OsAccountState::STOPPING},
    {OS_ACCOUNT_SUBSCRIBE_TYPE::STOPPED, OsAccountState::STOPPED},
    {OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHING, OsAccountState::SWITCHING},
    {OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHED, OsAccountState::SWITCHED},
    {OS_ACCOUNT_SUBSCRIBE_TYPE::CREATING, OsAccountState::CREATING},
    {OS_ACCOUNT_SUBSCRIBE_TYPE::LOCKING, OsAccountState::LOCKING},
    {OS_ACCOUNT_SUBSCRIBE_TYPE::LOCKED, OsAccountState::LOCKED}
};

bool PublishOsAccountStateByType(const uint8_t *data, size_t size,
    OsAccountSubscribeManager &manager, OS_ACCOUNT_SUBSCRIBE_TYPE selectedType, sptr<IRemoteObject> eventListener)
{
    FuzzData fuzzData(data, size);
    int32_t fromId = fuzzData.GetData<int32_t>();
    int32_t toId = fuzzData.GetData<int32_t>();
    OsAccountState targetState;
    auto it = SUBSCRIBE_TO_STATE_MAP.find(selectedType);
    if (it != SUBSCRIBE_TO_STATE_MAP.end()) {
        targetState = it->second;
    } else {
        int32_t randomStateValue = (fuzzData.GetData<int32_t>() % CONSTANTS_STATE_MAX) - 1;
        targetState = static_cast<OsAccountState>(randomStateValue);
    }
    manager.Publish(fromId, targetState, toId);
    manager.UnsubscribeOsAccount(eventListener);
    return true;
}

bool OsAccountSubscribeTypeSpecificFuzzTest(const uint8_t *data, size_t size)
{
    auto &manager = OsAccountSubscribeManager::GetInstance();
    OS_ACCOUNT_SUBSCRIBE_TYPE selectedType;
    sptr<IRemoteObject> eventListener;

    if (!SetupOsAccountSubscription(data, size, manager, selectedType, eventListener)) {
        return false;
    }

    return PublishOsAccountStateByType(data, size, manager, selectedType, eventListener);
}

bool UnsubscribeOsAccountStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    MessageParcel datas;
    datas.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR);
    FuzzData fuzzData(data, size);

    sptr<OsAccountEventListener> listener = new (std::nothrow) TestOsAccountEventListener();
    if (listener == nullptr) {
        return false;
    }
    sptr<IRemoteObject> osAccountEventListener = listener->AsObject();

    if (!datas.WriteRemoteObject(osAccountEventListener)) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;

    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
    osAccountManagerService_->OnRemoteRequest(
        static_cast<int32_t>(IOsAccountIpcCode::COMMAND_UNSUBSCRIBE_OS_ACCOUNT), datas, reply, option);

    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::SubscribeOsAccountStubFuzzTest(data, size);
    OHOS::OsAccountSubscribeManagerFuzzTest(data, size);
    OHOS::UnsubscribeOsAccountStubFuzzTest(data, size);
    OHOS::OsAccountSubscribeTypeSpecificFuzzTest(data, size);
    return 0;
}
