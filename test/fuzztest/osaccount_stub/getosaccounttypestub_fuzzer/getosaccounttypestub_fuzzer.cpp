/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "getosaccounttypestub_fuzzer.h"
#include <string>
#include <thread>
#include <vector>

#include "fuzz_data.h"
#include "ios_account.h"
#include "os_account_info_json_parser.h"
#include "os_account_manager_service.h"

using namespace std;
using namespace OHOS::AccountSA;

namespace OHOS {
const std::u16string IOS_ACCOUNT_DESCRIPTOR = u"ohos.accountfwk.IOsAccount";
bool GetOsAccountTypeStubFuzzTest(const uint8_t *data, size_t size)
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

    osAccountManagerService_ ->OnRemoteRequest(
        static_cast<int32_t>(IOsAccountIpcCode::COMMAND_GET_OS_ACCOUNT_TYPE), datas, reply, option);

    return true;
}

bool ReadOsAccountInfo(MessageParcel &data, OsAccountInfo &accountInfo)
{
    StringRawData stringRawData;

    data.ReadInt32();
    if (!data.ReadUint32(stringRawData.size)) {
        return false;
    }
    auto readstringRawData = data.ReadRawData(stringRawData.size);
    if (readstringRawData == nullptr) {
        return false;
    }
    ErrCode stringRawDataoutError = stringRawData.RawDataCpy(readstringRawData);
    if (stringRawDataoutError) {
        return false;
    }

    std::string accountStr;
    stringRawData.Unmarshalling(accountStr);
    auto jsonObject = CreateJsonFromString(accountStr);
    if (jsonObject == nullptr) {
        return false;
    }
    FromJson(jsonObject.get(), accountInfo);
    return true;
}

void SendRequestWithCode(int32_t code)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR);
    MessageOption option;
    MessageParcel reply;
    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
    osAccountManagerService_->OnRemoteRequest(code, datas, reply, option);
}

void CheckOsAccountStatus()
{
    OsAccountInfo osAccountInfoOne;
    OsAccountType testType = OsAccountType::NORMAL;
    std::string accountName = "getosaccounttypestub_test_account";
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR);
    data.WriteString16(Str8ToStr16(accountName));
    data.WriteInt32(static_cast<int32_t>(testType));
    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
    osAccountManagerService_->OnRemoteRequest(
        static_cast<int32_t>(IOsAccountIpcCode::COMMAND_CREATE_OS_ACCOUNT), data, reply, option);
    if (!ReadOsAccountInfo(reply, osAccountInfoOne)) {
        return;
    }
    SendRequestWithCode(static_cast<int32_t>(IOsAccountIpcCode::COMMAND_GET_OS_ACCOUNT_TYPE));
    SendRequestWithCode(static_cast<int32_t>(IOsAccountIpcCode::COMMAND_GET_OS_ACCOUNT_NAME));
    SendRequestWithCode(static_cast<int32_t>(IOsAccountIpcCode::COMMAND_GET_OS_ACCOUNT_SHORT_NAME));
    SendRequestWithCode(static_cast<int32_t>(IOsAccountIpcCode::COMMAND_GET_FOREGROUND_OS_ACCOUNTS));
}
} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::CheckOsAccountStatus();
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::GetOsAccountTypeStubFuzzTest(data, size);
    return 0;
}
