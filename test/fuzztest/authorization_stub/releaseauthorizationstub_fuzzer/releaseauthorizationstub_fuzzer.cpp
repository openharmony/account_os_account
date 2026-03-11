/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "releaseauthorizationstub_fuzzer.h"
#include <cstddef>
#include <string>
#include <vector>
#include "account_log_wrapper.h"
#include "authorization_common.h"
#include "authorization_manager_service.h"
#include "fuzz_data.h"

using namespace std;
using namespace OHOS::AccountSA;

namespace OHOS {
const std::u16string AUTHORIZATION_TOKEN = u"ohos.accountfwk.IAuthorization";

bool ReleaseAuthorizationStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    FuzzData fuzzData(data, size);
    MessageParcel dataTemp;
    MessageParcel reply;
    MessageOption option;

    if (!dataTemp.WriteInterfaceToken(AUTHORIZATION_TOKEN)) {
        return false;
    }

    std::string privilege = fuzzData.GenerateString();
    if (!dataTemp.WriteString(privilege)) {
        return false;
    }

    uint32_t code = 1;
    auto service = std::make_shared<AuthorizationManagerService>();
    service->OnRemoteRequest(code, dataTemp, reply, option);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::ReleaseAuthorizationStubFuzzTest(data, size);
    return 0;
}
