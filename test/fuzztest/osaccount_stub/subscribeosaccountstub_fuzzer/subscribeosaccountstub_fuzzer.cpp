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

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_kit.h"
#include "fuzz_data.h"
#include "ios_account.h"
#include "nativetoken_kit.h"
#include "os_account_event_listener.h"
#include "os_account_manager_service.h"
#include "os_account_subscriber.h"
#include "os_account_subscribe_manager.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::AccountSA;
using namespace OHOS::Security::AccessToken;

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
        return ERR_OK;
    }
    OHOS::ErrCode OnAccountsSwitch(int newId, int oldId) override
    {
        return OHOS::ERR_OK;
    }
};

namespace OHOS {
const int CONSTANTS_STATE_MAX = 13;
const int CONSTANTS_SUBSCRIBE_TYPE_MAX = 13;
constexpr uint32_t MAX_STATE_PUBLISH_COUNT = 100;
constexpr uint32_t MIN_STATE_PUBLISH_COUNT = 1;
constexpr int32_t PERMISSION_COUNT_NUM = 2;
constexpr int32_t FIRST_PARAM_INDEX = 0;
constexpr int32_t SECOND_PARAM_INDEX = 1;
const std::u16string IOS_ACCOUNT_DESCRIPTOR = u"ohos.accountfwk.IOsAccount";
bool SubscribeOsAccountStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    MessageParcel datas;
    datas.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR);
    FuzzData fuzzData(data, size);

    auto useOsAccountSubscribeInfo = fuzzData.GenerateBool();
    if (useOsAccountSubscribeInfo) {
        OsAccountSubscribeInfo subscribeInfo;
        subscribeInfo.SetName(fuzzData.GenerateString());
        int32_t subscribeTypeValue = (fuzzData.GetData<int32_t>() % CONSTANTS_SUBSCRIBE_TYPE_MAX) - 1;
        OS_ACCOUNT_SUBSCRIBE_TYPE testType = static_cast<OS_ACCOUNT_SUBSCRIBE_TYPE>(subscribeTypeValue);
        subscribeInfo.SetOsAccountSubscribeType(testType);
        if (!datas.WriteParcelable(&subscribeInfo)) {
            return false;
        }
    }
    auto useOsAccountEventListener = fuzzData.GenerateBool();
    if (useOsAccountEventListener) {
        sptr<OsAccountEventListener> listener = new (std::nothrow) OsAccountEventListener();
        if (listener == nullptr) {
            return false;
        }
        sptr<IRemoteObject> osAccountEventListener = listener->AsObject();
        if (!datas.WriteRemoteObject(osAccountEventListener)) {
            return false;
        }
    }

    MessageParcel reply;
    MessageOption option;

    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();

    osAccountManagerService_ ->OnRemoteRequest(
        static_cast<int32_t>(IOsAccountIpcCode::COMMAND_SUBSCRIBE_OS_ACCOUNT), datas, reply, option);

    return true;
}

bool UnsubscribeOsAccountStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    MessageParcel datas;
    datas.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR);
    FuzzData fuzzData(data, size);

    auto useOsAccountEventListener = fuzzData.GenerateBool();
    if (useOsAccountEventListener) {
        sptr<OsAccountEventListener> listener = new (std::nothrow) TestOsAccountEventListener();
        if (listener == nullptr) {
            return false;
        }
        sptr<IRemoteObject> osAccountEventListener = listener->AsObject();
        if (!datas.WriteRemoteObject(osAccountEventListener)) {
            return false;
        }
    }

    MessageParcel reply;
    MessageOption option;

    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
    osAccountManagerService_->OnRemoteRequest(
        static_cast<int32_t>(IOsAccountIpcCode::COMMAND_UNSUBSCRIBE_OS_ACCOUNT), datas, reply, option);

    return true;
}

bool OsAccountSubscribeFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzData fuzzData(data, size);

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

    OsAccountSubscribeManager::GetInstance().SubscribeOsAccount(subscribeInfo, eventListener);

    uint32_t stateCount = (fuzzData.GetData<uint32_t>() % MAX_STATE_PUBLISH_COUNT) + MIN_STATE_PUBLISH_COUNT;

    for (uint32_t i = 0; i < stateCount; i++) {
        int32_t stateValue = (fuzzData.GetData<int32_t>() % CONSTANTS_STATE_MAX) - 1;
        OsAccountState randomState = static_cast<OsAccountState>(stateValue);
        int32_t randomFromId = fuzzData.GetData<int32_t>();
        int32_t randomToId = fuzzData.GetData<int32_t>();

        OsAccountSubscribeManager::GetInstance().Publish(randomFromId, randomState, randomToId);
    }

    OsAccountSubscribeManager::GetInstance().UnsubscribeOsAccount(eventListener);
    return true;
}

bool OsAccountSubscribeWithHandshakeFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzData fuzzData(data, size);

    std::set<OsAccountState> states = { OsAccountState::STOPPING, OsAccountState::CREATED, OsAccountState::SWITCHING,
        OsAccountState::SWITCHED, OsAccountState::UNLOCKED, OsAccountState::STOPPED, OsAccountState::REMOVED,
        OsAccountState::LOCKING, OsAccountState::LOCKED};
    auto subscribeInfo = std::make_shared<OsAccountSubscribeInfo>(states, fuzzData.GetData<bool>());
    sptr<OsAccountEventListener> listener = new (std::nothrow) TestOsAccountEventListener();
    if (listener == nullptr) {
        return false;
    }
    sptr<IRemoteObject> eventListener = listener->AsObject();
    OsAccountSubscribeManager::GetInstance().SubscribeOsAccount(subscribeInfo, eventListener);

    int32_t fromId = fuzzData.GetData<int32_t>();
    int32_t toId = fuzzData.GetData<int32_t>();
    OsAccountState targetState = static_cast<OsAccountState>((fuzzData.GetData<int32_t>() % CONSTANTS_STATE_MAX) - 1);
    OsAccountSubscribeManager::GetInstance().Publish(fromId, targetState, toId);
    OsAccountSubscribeManager::GetInstance().UnsubscribeOsAccount(eventListener);
    return true;
}
} // namespace OHOS

void NativeTokenGet()
{
    uint64_t tokenId;
    const char **perms = new const char *[PERMISSION_COUNT_NUM];
    perms[FIRST_PARAM_INDEX] = "ohos.permission.MANAGE_LOCAL_ACCOUNTS";
    perms[SECOND_PARAM_INDEX] = "ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = PERMISSION_COUNT_NUM,
        .aclsNum = 0,
        .perms = perms,
        .acls = nullptr,
        .aplStr = "system_core",
    };
    infoInstance.processName = "RegisterInputer";
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    AccessTokenKit::ReloadNativeTokenInfo();
    delete[] perms;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    NativeTokenGet();
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::SubscribeOsAccountStubFuzzTest(data, size);
    OHOS::UnsubscribeOsAccountStubFuzzTest(data, size);
    OHOS::OsAccountSubscribeFuzzTest(data, size);
    OHOS::OsAccountSubscribeWithHandshakeFuzzTest(data, size);
    return 0;
}
