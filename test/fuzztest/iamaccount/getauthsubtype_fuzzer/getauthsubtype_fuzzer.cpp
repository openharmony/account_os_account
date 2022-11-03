/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "getauthsubtype_fuzzer.h"

#include <string>
#include <vector>
#include "account_iam_client.h"


using namespace std;
using namespace OHOS::AccountSA;

namespace OHOS {
    bool GetAuthSubTypeFuzzTest(const uint8_t* data, size_t size)
    {
        int32_t userId = static_cast<int32_t>(size);
        int32_t result = AccountIAMClient::GetInstance().GetAuthSubType(userId);
        return result == ERR_OK;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GetAuthSubTypeFuzzTest(data, size);
    return 0;
}

