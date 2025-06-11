/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "procgetaccountserverconfigstub_fuzzer.h"

#include <string>
#include <vector>

#include "domain_account_callback.h"
#include "domain_account_callback_service.h"
#include "domain_account_manager_service.h"
#include "fuzz_data.h"
#include "idomain_account.h"

using namespace std;
using namespace OHOS::AccountSA;

namespace OHOS {
bool ProcGetAccountServerConfigStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    DomainAccountInfo info;
    FuzzData fuzzData(data, size);
    info.accountId_ = fuzzData.GenerateString();
    info.accountName_ = fuzzData.GenerateString();
    info.domain_ = fuzzData.GenerateString();
    info.serverConfigId_ = fuzzData.GenerateString();
    MessageParcel dataTemp;
    if (!dataTemp.WriteInterfaceToken(DomainAccountStub::GetDescriptor())) {
        return false;
    }
    if (!dataTemp.WriteParcelable(&info)) {
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(IDomainAccountIpcCode::COMMAND_GET_ACCOUNT_SERVER_CONFIG);
    auto domainAccountService = std::make_shared<DomainAccountManagerService>();
    domainAccountService->OnRemoteRequest(code, dataTemp, reply, option);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::ProcGetAccountServerConfigStubFuzzTest(data, size);
    return 0;
}

