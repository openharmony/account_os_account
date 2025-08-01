/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "querydistributedvirtualdeviceid_fuzzer.h"

#include <cstdint>
#include "os_account_manager.h"
#include "account_log_wrapper.h"
#include "os_account_constants.h"
#include "fuzz_data.h"
#include <string>
#include <vector>
#include "securec.h"

using namespace std;
using namespace OHOS::AccountSA;

namespace OHOS {
    bool QueryDistributedVirtualDeviceIdFuzzTest(const uint8_t* data, size_t size)
    {
        int32_t result = ERR_OK;
        if ((data != nullptr) && (size != 0)) {
            FuzzData fuzzData(data, size);
            OsAccountInfo osAccountInfoOne;
            std::string dvid;
            std::string bundleName(fuzzData.GenerateString());
            int32_t localId = 100;
            result = OsAccountManager::QueryDistributedVirtualDeviceId(bundleName, localId, dvid);
            dvid = bundleName;
            result = OsAccountManager::GetDistributedVirtualDeviceId(dvid);
        }
        return result == ERR_OK;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::QueryDistributedVirtualDeviceIdFuzzTest(data, size);
    return 0;
}