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

#include "deactivateosaccountstub_fuzzer.h"
#include <string>
#include <thread>
#include <vector>

#include "fuzz_data.h"
#include "ios_account.h"
#include "os_account_manager_service.h"

using namespace std;
using namespace OHOS::AccountSA;

namespace OHOS {
const std::u16string IOS_ACCOUNT_DESCRIPTOR = u"ohos.accountfwk.IOsAccount";
const int START_USER_ID = 100;
bool DeactivateOsAccountStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    MessageParcel datas;
    datas.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR);
    FuzzData fuzzData(data, size);
    if (!datas.WriteInt32(fuzzData.GetData<int32_t>())) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;

    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();

    osAccountManagerService_->OnRemoteRequest(
        static_cast<int32_t>(IOsAccountIpcCode::COMMAND_DEACTIVATE_OS_ACCOUNT), datas, reply, option);

    return true;
}

void IsOsAccountDeactivating()
{
    MessageParcel dataParcel;
    dataParcel.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR);
    dataParcel.WriteInt32(START_USER_ID);
    MessageParcel reply;
    MessageOption option;
    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
    osAccountManagerService_->OnRemoteRequest(
        static_cast<uint32_t>(IOsAccountIpcCode::COMMAND_IS_OS_ACCOUNT_DEACTIVATING),
        dataParcel, reply, option);
}

void IsCurrentOsAccountVerified()
{
    MessageParcel datas;
    datas.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR);
    MessageOption option;
    MessageParcel reply;
    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
    osAccountManagerService_->OnRemoteRequest(
        static_cast<uint32_t>(IOsAccountIpcCode::COMMAND_IS_CURRENT_OS_ACCOUNT_VERIFIED),
        datas, reply, option);
}
} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::IsOsAccountDeactivating();
    OHOS::IsCurrentOsAccountVerified();
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::DeactivateOsAccountStubFuzzTest(data, size);
    return 0;
}
