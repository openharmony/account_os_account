/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "checkappaccountsyncenablestub_fuzzer.h"

#include "account_log_wrapper.h"
#include "app_account_manager_service.h"
#include "iapp_account.h"
#include <string>
#include <vector>

using namespace std;
using namespace OHOS::AccountSA;
namespace OHOS {
const std::u16string APPACCOUNT_TOKEN = u"ohos.accountfwk.IAppAccount";
bool CheckAppAccountSyncEnableStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    MessageParcel dataTemp;
    if (!dataTemp.WriteInterfaceToken(APPACCOUNT_TOKEN)) {
        return false;
    }
    std::string name(reinterpret_cast<const char*>(data), size);
    if (!dataTemp.WriteString(name)) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(AppAccountInterfaceCode::CHECK_APP_ACCOUNT_SYNC_ENABLE);
    auto appAccountManagerService = std::make_shared<AppAccountManagerService>();
    appAccountManagerService->OnRemoteRequest(code, dataTemp, reply, option);
    
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::CheckAppAccountSyncEnableStubFuzzTest(data, size);
    return 0;
}

