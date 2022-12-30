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

#include "getcredentialinfo_fuzzer.h"

#include <string>
#include <vector>
#include "account_iam_client.h"


using namespace std;
using namespace OHOS::AccountSA;

class MockIDMCallback : public OHOS::AccountSA::GetCredInfoCallback {
public:
    virtual ~MockIDMCallback() {}
    void OnCredentialInfo(int32_t result, const std::vector<CredentialInfo> &infoList) override
    {
        return;
    }
};

namespace OHOS {
    bool GetCredentialInfoFuzzTest(const uint8_t* data, size_t size)
    {
        int32_t userId = static_cast<int32_t>(size);
        AuthType authType = static_cast<AuthType>(size);
        std::shared_ptr<GetCredInfoCallback> callback = make_shared<MockIDMCallback>();
        int32_t result = AccountIAMClient::GetInstance().GetCredentialInfo(userId, authType, callback);
        return result == ERR_OK;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GetCredentialInfoFuzzTest(data, size);
    return 0;
}

