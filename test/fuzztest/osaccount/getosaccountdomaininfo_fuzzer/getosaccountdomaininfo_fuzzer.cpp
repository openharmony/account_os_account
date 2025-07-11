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

#include "getosaccountdomaininfo_fuzzer.h"

#include <string>
#include <vector>
#include "account_log_wrapper.h"
#include "fuzz_data.h"
#include "os_account_constants.h"
#include "os_account_manager.h"

using namespace std;
using namespace OHOS::AccountSA;

const int32_t MAX_TEST_ID = 10738; // Maximum test ID for fuzzing

namespace OHOS {
void GetOsAccountDomainInfoFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    DomainAccountInfo domainInfo;
    FuzzData fuzzData(data, size);
    int32_t testId = fuzzData.GetData<bool>() ?
        (fuzzData.GetData<int32_t>() % MAX_TEST_ID) : fuzzData.GetData<int32_t>();
    OsAccountManager::GetOsAccountDomainInfo(testId, domainInfo);
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GetOsAccountDomainInfoFuzzTest(data, size);
    return 0;
}

