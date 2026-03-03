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
#include "checkauthorizationtoken_fuzzer.h"
#include <cstddef>
#include <string>
#include <vector>
#include "account_log_wrapper.h"
#include "authorization_client.h"
#include "authorization_common.h"
#include "fuzz_data.h"

using namespace std;
using namespace OHOS::AccountSA;

namespace OHOS {
bool CheckAuthorizationTokenFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    FuzzData fuzzData(data, size);
    std::string privilege = fuzzData.GenerateString();
    std::int32_t pid = fuzzData.GetData<int32_t>();

    std::vector<uint8_t> token;
    uint32_t tokenSize = fuzzData.GetData<uint32_t>() % 128;
    for (uint32_t i = 0; i < tokenSize; i++) {
        token.push_back(fuzzData.GetData<uint8_t>());
    }

    CheckAuthorizationResult authResult;
    authResult.challenge = {};
    authResult.iamToken = {};
    authResult.isAuthorized = false;

    AuthorizationClient::GetInstance().CheckAuthorizationToken(token, privilege, pid, authResult);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::CheckAuthorizationTokenFuzzTest(data, size);
    return 0;
}
