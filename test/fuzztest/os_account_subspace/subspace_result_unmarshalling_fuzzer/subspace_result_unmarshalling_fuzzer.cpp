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

#include "subspace_result_unmarshalling_fuzzer.h"

#include <string>
#include <vector>
#include "account_log_wrapper.h"
#include "account_info.h"
#include "fuzz_data.h"
#include "message_parcel.h"

using namespace std;
using namespace OHOS::AccountSA;

namespace OHOS {
bool SubspaceResultUnmarshallingFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    FuzzData fuzzData(data, size);

    MessageParcel parcel;
    /* Decide write strategy: 0=empty, 1=write N int32, 2=write raw bytes */
    uint8_t strategy = fuzzData.GetData<uint8_t>() % 3;
    if (strategy == 0) {
        /* Empty parcel — Write nothing */
    } else if (strategy == 1) {
        /* Write 0~4 int32 values */
        uint8_t count = fuzzData.GetData<uint8_t>() % 5;
        for (uint8_t i = 0; i < count; i++) {
            parcel.WriteInt32(fuzzData.GetData<int32_t>());
        }
    } else {
        /* Write remaining raw bytes */
        size_t remaining = size - fuzzData.pos_;
        if (remaining > 0) {
            parcel.WriteBuffer(data + fuzzData.pos_, remaining);
        }
    }

    OsAccountSubspaceResult* result = OsAccountSubspaceResult::Unmarshalling(parcel);
    if (result != nullptr) {
        delete result;
    }

    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SubspaceResultUnmarshallingFuzzTest(data, size);
    return 0;
}
