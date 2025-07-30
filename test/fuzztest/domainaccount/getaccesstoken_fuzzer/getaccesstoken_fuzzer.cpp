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

#include "getaccesstoken_fuzzer.h"

#include "account_log_wrapper.h"
#include "domain_account_client.h"
#include "fuzz_data.h"
#include <string>

using namespace std;
using namespace OHOS::AccountSA;

namespace OHOS {
namespace {
const int ENUM_MAX = 4;
class TestGetAccessTokenCallback : public GetAccessTokenCallback {
public:
    TestGetAccessTokenCallback() {};
    virtual ~TestGetAccessTokenCallback() {};
    void OnResult(const int32_t errCode, const std::vector<uint8_t> &accessToken) {};
};
}
bool GetAccessTokenFuzzTest(const uint8_t* data, size_t size)
{
    bool ret = true;
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    FuzzData fuzzData(data, size);
    DomainAccountInfo info;
    info.domain_ = fuzzData.GenerateString();
    info.accountName_ = fuzzData.GenerateString();
    info.accountId_ = fuzzData.GenerateString();
    info.isAuthenticated = fuzzData.GenerateBool();
    info.serverConfigId_ = fuzzData.GenerateString();
    int typeNumber = fuzzData.GetData<int>() % ENUM_MAX;
    info.status_ = static_cast<DomainAccountStatus>(typeNumber);
    AAFwk::WantParams parameters;
    std::shared_ptr<GetAccessTokenCallback> callback = std::make_shared<TestGetAccessTokenCallback>();
    ret = DomainAccountClient::GetInstance().GetAccessToken(info, parameters, callback);
    return ret == ERR_OK;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GetAccessTokenFuzzTest(data, size);
    return 0;
}

