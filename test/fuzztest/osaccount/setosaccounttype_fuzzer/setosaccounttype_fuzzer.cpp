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

#include "setosaccounttype_fuzzer.h"

#include "os_account_manager.h"
#include "account_log_wrapper.h"
#include "fuzz_data.h"
#include "os_account_constants.h"
#include <cstdint>
#include <string>
#include <vector>

using namespace std;
using namespace OHOS::AccountSA;

namespace {
    // Maximum token size for fuzzing (matches MAX_TOKEN_SIZE in tee_auth_adapter.h)
    constexpr size_t MAX_FUZZ_TOKEN_SIZE = 1024;  // 1KB, matching tee_auth_adapter.h
}

namespace OHOS {
    bool SetOsAccountTypeFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size < sizeof(int32_t) + sizeof(uint32_t))) {
            return false;
        }

        FuzzData fuzzData(data, size);

        // Generate test account ID (allow negative values for boundary testing)
        int32_t testId = fuzzData.GetData<int32_t>();

        // Generate account type using enum range
        uint32_t typeInt = fuzzData.GetData<uint32_t>();
        constexpr int32_t maxType = static_cast<int32_t>(OsAccountType::END) - 1;
        OsAccountType type = static_cast<OsAccountType>(typeInt % (maxType + 1));

        // Prepare token from remaining data
        SetOsAccountTypeOptions options;
        if (fuzzData.pos_ < size) {
            size_t tokenSize = size - fuzzData.pos_;
            // Limit token size to prevent performance issues
            if (tokenSize > MAX_FUZZ_TOKEN_SIZE) {
                tokenSize = MAX_FUZZ_TOKEN_SIZE;
            }

            options.token = std::vector<uint8_t>();
            options.token->reserve(tokenSize);
            for (size_t i = 0; i < tokenSize; ++i) {
                options.token->push_back(fuzzData.GetData<uint8_t>());
            }
        }

        // Call API and ignore result - focus on crash detection
        (void)OsAccountManager::SetOsAccountType(testId, type, options);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SetOsAccountTypeFuzzTest(data, size);
    return 0;
}
