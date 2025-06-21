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

#include "checkosaccountconstraintenabledstub_fuzzer.h"
#include <string>
#include <thread>
#include <vector>

#include "fuzz_data.h"
#include "ios_account.h"
#include "os_account_manager_service.h"

using namespace std;
using namespace OHOS::AccountSA;

namespace OHOS {
const int ENUM_MAX = 5;
const int PRIVATE_NUMBER = 3;
const int END_NUMBER = 4;
const std::u16string IOS_ACCOUNT_DESCRIPTOR = u"ohos.accountfwk.IOsAccount";
bool CheckOsAccountConstraintEnabledStubFuzzTest(const uint8_t *data, size_t size)
{
    MessageParcel datas;
    if ((data == nullptr) || (size == 0) || (!datas.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR))) {
        return false;
    }
    FuzzData fuzzData(data, size);
    if (!datas.WriteInt32(fuzzData.GetData<int32_t>())) {
        return false;
    }
    if (!datas.WriteString(fuzzData.GenerateString())) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
    osAccountManagerService_ ->OnRemoteRequest(
        static_cast<int32_t>(IOsAccountIpcCode::COMMAND_CHECK_OS_ACCOUNT_CONSTRAINT_ENABLED), datas, reply, option);

    return true;
}

bool ProcUpdateOsAccountWithFullInfoStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR)) {
        return false;
    }

    FuzzData fuzzData(data, size);

    OsAccountInfo osAccountInfo;
    osAccountInfo.SetLocalId(fuzzData.GetData<int>());
    osAccountInfo.SetLocalName(fuzzData.GenerateString());
    osAccountInfo.SetShortName(fuzzData.GenerateString());
    int typeNumber = fuzzData.GetData<int>() % ENUM_MAX;
    if (typeNumber == PRIVATE_NUMBER) {
        osAccountInfo.SetType(PRIVATE);
    } else if (typeNumber == END_NUMBER) {
        osAccountInfo.SetType(END);
    } else {
        OsAccountType testType = static_cast<OsAccountType>(typeNumber);
        osAccountInfo.SetType(testType);
    }
    osAccountInfo.SetSerialNumber(fuzzData.GetData<int64_t>());

    if (!datas.WriteParcelable(&osAccountInfo)) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
    osAccountManagerService_->OnRemoteRequest(
        static_cast<int32_t>(IOsAccountIpcCode::COMMAND_UPDATE_OS_ACCOUNT_WITH_FULL_INFO), datas, reply, option);

    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::CheckOsAccountConstraintEnabledStubFuzzTest(data, size);
    OHOS::ProcUpdateOsAccountWithFullInfoStubFuzzTest(data, size);
    return 0;
}
