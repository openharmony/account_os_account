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

#include "authclient_fuzzer.h"

#include "account_log_wrapper.h"
#include "domain_account_client.h"
#include "fuzz_data.h"
#include <string>

using namespace std;
using namespace OHOS::AccountSA;

namespace OHOS {
namespace {
const int ENUM_MAX = 4;
const int TEST_ENUM = 5;
class TestDomainAccountCallback : public DomainAccountCallback {
public:
    TestDomainAccountCallback() {};
    virtual ~TestDomainAccountCallback() {}
    void OnResult(const int32_t errCode, Parcel &parcel) override {}
};
}
bool AuthFuzzTest(const uint8_t* data, size_t size)
{
    bool result = false;
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
    int typeNumber = fuzzData.GenerateBool() ? TEST_ENUM : fuzzData.GetData<int>() % ENUM_MAX;
    info.status_ = static_cast<DomainAccountStatus>(typeNumber);

    std::vector<uint8_t> password = {fuzzData.GetData<uint8_t>(), fuzzData.GetData<uint8_t>()};
    std::shared_ptr<DomainAccountCallback> callback = std::make_shared<TestDomainAccountCallback>();
    result = DomainAccountClient::GetInstance().Auth(info, password, callback);
    return result == ERR_OK;
}

bool AuthUserFuzzTest(const uint8_t* data, size_t size)
{
    bool result = false;
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    FuzzData fuzzData(data, size);
    int32_t userId = fuzzData.GetData<int32_t>();
    std::vector<uint8_t> password = {fuzzData.GetData<uint8_t>(), fuzzData.GetData<uint8_t>()};
    std::shared_ptr<DomainAccountCallback> callback = std::make_shared<TestDomainAccountCallback>();
    uint64_t contextId = 0;
    result = DomainAccountClient::GetInstance().AuthUser(userId, password, callback, contextId);
    result = DomainAccountClient::GetInstance().CancelAuth(contextId);
    return result == ERR_OK;
}

bool AuthWithPopupFuzzTest(const uint8_t* data, size_t size)
{
    bool result = false;
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    FuzzData fuzzData(data, size);
    int32_t userId = fuzzData.GetData<int32_t>();
    std::shared_ptr<DomainAccountCallback> callback = std::make_shared<TestDomainAccountCallback>();
    result = DomainAccountClient::GetInstance().AuthWithPopup(userId, callback);
    return result == ERR_OK;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AuthFuzzTest(data, size);
    OHOS::AuthUserFuzzTest(data, size);
    OHOS::AuthWithPopupFuzzTest(data, size);
    return 0;
}

