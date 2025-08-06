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

#include "getallaccessibleaccountsstub_fuzzer.h"

#include <string>
#include <vector>

#include "account_log_wrapper.h"
#include "app_account_manager_service.h"
#include "fuzz_data.h"
#include "iapp_account.h"

using namespace std;
using namespace OHOS::AccountSA;
namespace OHOS {
const std::u16string APPACCOUNT_TOKEN = u"OHOS.AccountSA.IAppAccount";
const int CONST_NUMBER_ONE = 1;
bool GetAllAccessibleAccountsStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    MessageParcel dataTemp;
    FuzzData fuzzData(data, size);
    auto token = APPACCOUNT_TOKEN;
    auto isWriteCorrectToken = fuzzData.GetData<bool>();
    if (!isWriteCorrectToken) {
        token.append(CONST_NUMBER_ONE, fuzzData.GetData<char16_t>());
    }
    if (!dataTemp.WriteInterfaceToken(token)) {
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(IAppAccountIpcCode::COMMAND_GET_ALL_ACCESSIBLE_ACCOUNTS);
    auto appAccountManagerService = std::make_shared<AppAccountManagerService>();
    appAccountManagerService->OnRemoteRequest(code, dataTemp, reply, option);
    return true;
}

bool QueryAllAccessibleAccountsStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    MessageParcel dataTemp;
    if (!dataTemp.WriteInterfaceToken(APPACCOUNT_TOKEN)) {
        return false;
    }
    FuzzData fuzzData(data, size);
    std::string owner = fuzzData.GenerateString();
    if (!dataTemp.WriteString(owner)) {
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(IAppAccountIpcCode::COMMAND_QUERY_ALL_ACCESSIBLE_ACCOUNTS);
    auto appAccountManagerService = std::make_shared<AppAccountManagerService>();
    appAccountManagerService->OnRemoteRequest(code, dataTemp, reply, option);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::GetAllAccessibleAccountsStubFuzzTest(data, size);
    OHOS::QueryAllAccessibleAccountsStubFuzzTest(data, size);
    return 0;
}
