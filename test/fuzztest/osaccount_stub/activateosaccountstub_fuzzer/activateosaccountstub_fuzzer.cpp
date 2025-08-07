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

#include "activateosaccountstub_fuzzer.h"
#include <string>
#include <thread>
#include <vector>

#include "fuzz_data.h"
#include "ios_account.h"
#include "os_account_info_json_parser.h"
#include "os_account_manager_service.h"

using namespace std;
using namespace OHOS::AccountSA;
const int32_t MAX_TEST_ID = 10738; // Maximum test

namespace OHOS {
const int ENUM_TYPE_MAX = 5;
const int PRIVATE_NUMBER = 3;
const int END_NUMBER = 4;
const std::u16string IOS_ACCOUNT_DESCRIPTOR = u"ohos.accountfwk.IOsAccount";
bool ActivateOsAccountStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    MessageParcel datas;
    FuzzData fuzzData(data, size);
    datas.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR);
    int32_t testId = fuzzData.GetData<bool>() ?
                (fuzzData.GetData<int32_t>() % MAX_TEST_ID) : fuzzData.GetData<int32_t>();
    if (!datas.WriteInt32(testId)) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
    osAccountManagerService_ ->OnRemoteRequest(
        static_cast<int32_t>(IOsAccountIpcCode::COMMAND_ACTIVATE_OS_ACCOUNT), datas, reply, option);

    return true;
}

bool ProcCreateOsAccountWithFullInfoStubFuzzTest(const uint8_t *data, size_t size)
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
    int typeNumber = fuzzData.GetData<int>() % ENUM_TYPE_MAX;
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
        static_cast<int32_t>(IOsAccountIpcCode::COMMAND_CREATE_OS_ACCOUNT_WITH_FULL_INFO), datas, reply, option);
    osAccountManagerService_->OnRemoteRequest(
        static_cast<int32_t>(IOsAccountIpcCode::COMMAND_CREATE_OS_ACCOUNT_WITH_FULL_INFO_IN_OSACCOUNTINFO),
        datas, reply, option);
    return true;
}

bool ProcGetCreatedOsAccountNumFromDatabaseStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR)) {
        return false;
    }

    FuzzData fuzzData(data, size);
    if (!datas.WriteString(fuzzData.GenerateString())) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
    osAccountManagerService_->OnRemoteRequest(static_cast<int32_t>(
        IOsAccountIpcCode::COMMAND_GET_CREATED_OS_ACCOUNT_NUM_FROM_DATABASE), datas, reply, option);

    return true;
}

bool ProcGetMaxAllowCreateIdFromDatabaseStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR)) {
        return false;
    }

    FuzzData fuzzData(data, size);
    if (!datas.WriteString(fuzzData.GenerateString())) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
    osAccountManagerService_->OnRemoteRequest(
        static_cast<int32_t>(IOsAccountIpcCode::COMMAND_GET_MAX_ALLOW_CREATE_ID_FROM_DATABASE), datas, reply, option);

    return true;
}

bool ProcGetOsAccountFromDatabaseStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR)) {
        return false;
    }

    FuzzData fuzzData(data, size);
    if (!datas.WriteString(fuzzData.GenerateString())) {
        return false;
    }

    if (!datas.WriteInt32(fuzzData.GetData<int32_t>())) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
    osAccountManagerService_->OnRemoteRequest(
        static_cast<int32_t>(IOsAccountIpcCode::COMMAND_GET_OS_ACCOUNT_FROM_DATABASE), datas, reply, option);

    return true;
}

bool ProcGetOsAccountListFromDatabaseStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR)) {
        return false;
    }

    FuzzData fuzzData(data, size);
    if (!datas.WriteString(fuzzData.GenerateString())) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
    osAccountManagerService_->OnRemoteRequest(
        static_cast<int32_t>(IOsAccountIpcCode::COMMAND_GET_OS_ACCOUNT_LIST_FROM_DATABASE), datas, reply, option);

    return true;
}

bool ProcGetSerialNumberFromDatabaseStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR)) {
        return false;
    }

    FuzzData fuzzData(data, size);
    if (!datas.WriteString(fuzzData.GenerateString())) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
    osAccountManagerService_->OnRemoteRequest(
        static_cast<int32_t>(IOsAccountIpcCode::COMMAND_GET_SERIAL_NUMBER_FROM_DATABASE), datas, reply, option);

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
    std::string accountName = "activateosaccountstub_test_account";
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
    SendRequestWithCode(static_cast<int32_t>(IOsAccountIpcCode::COMMAND_GET_DEFAULT_ACTIVATED_OS_ACCOUNT));
    SendRequestWithCode(static_cast<int32_t>(IOsAccountIpcCode::COMMAND_GET_BACKGROUND_OS_ACCOUNT_LOCAL_IDS));
    SendRequestWithCode(static_cast<int32_t>(IOsAccountIpcCode::COMMAND_GET_OS_ACCOUNT_LOCAL_ID_FROM_PROCESS));
    SendRequestWithCode(static_cast<int32_t>(IOsAccountIpcCode::COMMAND_GET_OS_ACCOUNT_SWITCH_MOD));
    SendRequestWithCode(static_cast<int32_t>(IOsAccountIpcCode::COMMAND_GET_OS_ACCOUNT_TYPE_FROM_PROCESS));
    SendRequestWithCode(static_cast<int32_t>(IOsAccountIpcCode::COMMAND_QUERY_ACTIVE_OS_ACCOUNT_IDS));
    SendRequestWithCode(static_cast<int32_t>(IOsAccountIpcCode::COMMAND_QUERY_ALL_CREATED_OS_ACCOUNTS));
    SendRequestWithCode(static_cast<int32_t>(IOsAccountIpcCode::COMMAND_QUERY_MAX_LOGGED_IN_OS_ACCOUNT_NUMBER));
    SendRequestWithCode(static_cast<int32_t>(IOsAccountIpcCode::COMMAND_IS_MAIN_OS_ACCOUNT));
    SendRequestWithCode(static_cast<int32_t>(IOsAccountIpcCode::COMMAND_IS_MULTI_OS_ACCOUNT_ENABLE));
    SendRequestWithCode(static_cast<int32_t>(IOsAccountIpcCode::COMMAND_DEACTIVATE_ALL_OS_ACCOUNTS));
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
    OHOS::ActivateOsAccountStubFuzzTest(data, size);
    OHOS::ProcGetCreatedOsAccountNumFromDatabaseStubFuzzTest(data, size);
    OHOS::ProcCreateOsAccountWithFullInfoStubFuzzTest(data, size);
    OHOS::ProcGetMaxAllowCreateIdFromDatabaseStubFuzzTest(data, size);
    OHOS::ProcGetOsAccountFromDatabaseStubFuzzTest(data, size);
    OHOS::ProcGetOsAccountListFromDatabaseStubFuzzTest(data, size);
    OHOS::ProcGetSerialNumberFromDatabaseStubFuzzTest(data, size);
    return 0;
}
