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

#include "getoauthtokenstub_fuzzer.h"

#include <string>
#include <vector>
#include "account_log_wrapper.h"
#include "app_account_manager_service.h"
#include "iapp_account.h"
#include "fuzz_data.h"

using namespace std;
using namespace OHOS::AccountSA;
namespace OHOS {
const std::u16string APPACCOUNT_TOKEN = u"OHOS.AccountSA.IAppAccount";
bool GetAuthTokenStubFuzzTest(const uint8_t* data, size_t size, uint32_t code)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    FuzzData fuzzData(data, size);
    std::string name = fuzzData.GenerateString();
    std::string owner = fuzzData.GenerateString();
    std::string authType = fuzzData.GenerateString();
    MessageParcel dataTemp;
    if (!dataTemp.WriteInterfaceToken(APPACCOUNT_TOKEN)) {
        return false;
    }
    if (!dataTemp.WriteString(name)) {
        return false;
    }
    if (!dataTemp.WriteString(owner)) {
        return false;
    }
    if (!dataTemp.WriteString(authType)) {
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    auto appAccountManagerService = std::make_shared<AppAccountManagerService>();
    appAccountManagerService->OnRemoteRequest(code, dataTemp, reply, option);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GetAuthTokenStubFuzzTest(data, size, static_cast<uint32_t>(IAppAccountIpcCode::COMMAND_GET_AUTH_TOKEN));
    OHOS::GetAuthTokenStubFuzzTest(data, size, static_cast<uint32_t>(IAppAccountIpcCode::COMMAND_GET_O_AUTH_TOKEN));
    return 0;
}

