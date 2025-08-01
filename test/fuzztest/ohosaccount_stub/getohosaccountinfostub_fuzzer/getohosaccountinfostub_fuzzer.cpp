/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "getohosaccountinfostub_fuzzer.h"

#define private public
#include "account_mgr_service.h"
#undef private
#include "account_info.h"
#include "account_log_wrapper.h"
#include "distributed_account_event_service.h"
#include "fuzz_data.h"
#include "ohos_account_kits.h"
#include <cstdint>
#include <string>
#include <vector>

using namespace std;
using namespace OHOS::AccountSA;
const std::u16string OHOS_ACCOUNT_DESCRIPTOR = u"ohos.accountfwk.IAccount";
const int32_t MAX_TEST_ID = 10738; // Maximum test ID for fuzzing
namespace OHOS {
bool QueryDistributedVirtualDeviceIdStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(OHOS_ACCOUNT_DESCRIPTOR)) {
        return false;
    }
    FuzzData fuzzData(data, size);
    int32_t localId = fuzzData.GetData<bool>() ?
                (fuzzData.GetData<int32_t>() % MAX_TEST_ID) : fuzzData.GetData<int32_t>();
    std::string bundleName = fuzzData.GenerateString();
    if (!datas.WriteString16(Str8ToStr16(bundleName))) {
        return false;
    }
    if (!datas.WriteInt32(localId)) {
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    auto accountManagerService_ = std::make_shared<AccountMgrService>();
    accountManagerService_->state_ = STATE_RUNNING;
    accountManagerService_->OnRemoteRequest(
        static_cast<int32_t>(IAccountIpcCode::COMMAND_QUERY_DISTRIBUTED_VIRTUAL_DEVICE_ID_IN_STRING_IN_INT_OUT_STRING),
        datas, reply, option);
    return true;
}

bool SubscribeDistributedAccountEvenStubtFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(OHOS_ACCOUNT_DESCRIPTOR);
    FuzzData fuzzData(data, size);
    int32_t type = fuzzData.GetData<bool>() ?
                (fuzzData.GetData<int32_t>() % 4) : fuzzData.GetData<int32_t>();
    if (!datas.WriteInt32(type)) {
        return false;
    }
    if (fuzzData.GenerateBool()) {
        if (!datas.WriteRemoteObject(DistributedAccountEventService::GetInstance()->AsObject())) {
            return false;
        }
    }
    MessageParcel reply;
    MessageOption option;
    auto accountManagerService_ = std::make_shared<AccountMgrService>();
    accountManagerService_->state_ = STATE_RUNNING;
    accountManagerService_ ->OnRemoteRequest(
        static_cast<int32_t>(IAccountIpcCode::COMMAND_SUBSCRIBE_DISTRIBUTED_ACCOUNT_EVENT), datas, reply, option);
    return true;
}

bool UnsubscribeDistributedAccountStubEventFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(OHOS_ACCOUNT_DESCRIPTOR);
    FuzzData fuzzData(data, size);
    int32_t type = fuzzData.GetData<bool>() ?
                (fuzzData.GetData<int32_t>() % 4) : fuzzData.GetData<int32_t>();
    if (!datas.WriteInt32(type)) {
        return false;
    }
    if (fuzzData.GenerateBool()) {
        if (!datas.WriteRemoteObject(DistributedAccountEventService::GetInstance()->AsObject())) {
            return false;
        }
    }
    MessageParcel reply;
    MessageOption option;
    auto accountManagerService_ = std::make_shared<AccountMgrService>();
    accountManagerService_->state_ = STATE_RUNNING;
    accountManagerService_ ->OnRemoteRequest(
        static_cast<int32_t>(IAccountIpcCode::COMMAND_UNSUBSCRIBE_DISTRIBUTED_ACCOUNT_EVENT), datas, reply, option);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::QueryDistributedVirtualDeviceIdStubFuzzTest(data, size);
    OHOS::SubscribeDistributedAccountEvenStubtFuzzTest(data, size);
    OHOS::UnsubscribeDistributedAccountStubEventFuzzTest(data, size);
    return 0;
}

