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

#include "createosaccountfordomainstub_fuzzer.h"
#include <string>
#include <thread>
#include <vector>

#include "domain_account_callback_service.h"
#include "fuzz_data.h"
#include "ios_account.h"
#include "os_account_info_json_parser.h"
#include "os_account_manager_service.h"

using namespace std;
using namespace OHOS::AccountSA;

namespace OHOS {
const int CONSTANTS_NUMBER_FIVE = 5;
const std::u16string IOS_ACCOUNT_DESCRIPTOR = u"ohos.accountfwk.IOsAccount";
bool CreateOsAccountForDomainStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzData fuzzData(data, size);
    DomainAccountInfo domainInfo(fuzzData.GenerateString(),
        fuzzData.GenerateString());
    OsAccountType testType = static_cast<OsAccountType>(fuzzData.GetData<size_t>() % CONSTANTS_NUMBER_FIVE);
    CreateOsAccountForDomainOptions options;
    MessageParcel datas;
    datas.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR);

    if (!datas.WriteInt32(testType)) {
        return false;
    }

    if (!datas.WriteParcelable(&domainInfo)) {
        return false;
    }
    std::shared_ptr<DomainAccountCallback> callbackPtr = nullptr;
    sptr<DomainAccountCallbackService> callbackService = new (std::nothrow) DomainAccountCallbackService(callbackPtr);
    if ((callbackService == nullptr) || (!datas.WriteRemoteObject(callbackService->AsObject()))) {
        return false;
    }
    if (!datas.WriteParcelable(&options)) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;

    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();

    osAccountManagerService_ ->OnRemoteRequest(
        static_cast<int32_t>(IOsAccountIpcCode::COMMAND_CREATE_OS_ACCOUNT_FOR_DOMAIN), datas, reply, option);

    return true;
}

void SendRequestWithAccountId(int32_t code, int id)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR);
    if (!datas.WriteInt32(id)) {
        return;
    }
    MessageOption option;
    MessageParcel reply;
    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
    osAccountManagerService_->OnRemoteRequest(code, datas, reply, option);
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

bool ReadOsAccountInfo(MessageParcel &data, OsAccountInfo &accountInfo)
{
    int32_t accountSize;
    if (!data.ReadInt32(accountSize)) {
        return false;
    }
    auto readRawData = data.ReadRawData(accountSize);
    if (readRawData == nullptr) {
        return false;
    }
    const char *accountData = reinterpret_cast<const char *>(readRawData);
    std::string accountJson = std::string(accountData, accountSize - 1);
    auto jsonObject = CreateJsonFromString(accountJson);
    if (jsonObject == nullptr) {
        return false;
    }
    FromJson(jsonObject.get(), accountInfo);

    return true;
}

void CheckOsAccountStatus()
{
    OsAccountInfo osAccountInfoOne;
    OsAccountType testType = OsAccountType::NORMAL;
    std::string accountName = "fordomainstub_test_account";
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR);
    data.WriteString(accountName);
    data.WriteInt32(static_cast<int32_t>(testType));
    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
    osAccountManagerService_->OnRemoteRequest(
        static_cast<int32_t>(IOsAccountIpcCode::COMMAND_CREATE_OS_ACCOUNT), data, reply, option);
    if (!ReadOsAccountInfo(reply, osAccountInfoOne)) {
        return;
    }
    int32_t localId = osAccountInfoOne.GetLocalId();
    SendRequestWithAccountId(static_cast<int32_t>(IOsAccountIpcCode::COMMAND_ACTIVATE_OS_ACCOUNT), localId);
    SendRequestWithAccountId(static_cast<int32_t>(IOsAccountIpcCode::COMMAND_DEACTIVATE_OS_ACCOUNT), localId);
    SendRequestWithCode(static_cast<int32_t>(IOsAccountIpcCode::COMMAND_GET_OS_ACCOUNT_TYPE));
    SendRequestWithCode(static_cast<int32_t>(IOsAccountIpcCode::COMMAND_GET_OS_ACCOUNT_NAME));
    SendRequestWithCode(static_cast<int32_t>(IOsAccountIpcCode::COMMAND_GET_OS_ACCOUNT_SHORT_NAME));
    SendRequestWithCode(static_cast<int32_t>(IOsAccountIpcCode::COMMAND_GET_FOREGROUND_OS_ACCOUNTS));
    SendRequestWithCode(static_cast<int32_t>(IOsAccountIpcCode::COMMAND_GET_CREATED_OS_ACCOUNTS_COUNT));
    SendRequestWithCode(static_cast<int32_t>(IOsAccountIpcCode::COMMAND_GET_OS_ACCOUNT_ALL_CONSTRAINTS));
    SendRequestWithCode(static_cast<int32_t>(IOsAccountIpcCode::COMMAND_GET_DEFAULT_ACTIVATED_OS_ACCOUNT));
    SendRequestWithCode(static_cast<int32_t>(IOsAccountIpcCode::COMMAND_GET_BACKGROUND_OS_ACCOUNT_LOCAL_IDS));
    SendRequestWithCode(static_cast<int32_t>(IOsAccountIpcCode::COMMAND_GET_OS_ACCOUNT_LOCAL_ID_FROM_PROCESS));
    SendRequestWithCode(static_cast<int32_t>(IOsAccountIpcCode::COMMAND_QUERY_CURRENT_OS_ACCOUNT));
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
    OHOS::CreateOsAccountForDomainStubFuzzTest(data, size);
    return 0;
}
