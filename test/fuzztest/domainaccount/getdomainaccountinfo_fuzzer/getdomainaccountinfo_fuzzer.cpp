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

#include "getdomainaccountinfo_fuzzer.h"

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_kit.h"
#include "domain_account_client.h"
#include "fuzz_data.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS::AccountSA;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace {
const int ENUM_MAX = 4;
class TestDomainAccountCallback : public DomainAccountCallback {
public:
    TestDomainAccountCallback() = default;
    virtual ~TestDomainAccountCallback() = default;
    void OnResult(const int32_t errCode, Parcel &parcel) override {}
};
}

bool GetDomainAccountInfoFuzzTest(const uint8_t* data, size_t size)
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
    int typeNumber = fuzzData.GetData<int>() % ENUM_MAX;
    info.status_ = static_cast<DomainAccountStatus>(typeNumber);
    std::shared_ptr<DomainAccountCallback> callback = nullptr;
    auto useCallback = fuzzData.GenerateBool();
    if (useCallback) {
        callback = std::make_shared<TestDomainAccountCallback>();
    }
    
    result = DomainAccountClient::GetInstance().GetDomainAccountInfo(info, callback);
    return result == ERR_OK;
}
}

void NativeTokenGet()
{
    uint64_t tokenId;
    const char **perms = new const char *[1];
    perms[0] = "ohos.permission.GET_DOMAIN_ACCOUNTS";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 1,
        .aclsNum = 0,
        .perms = perms,
        .acls = nullptr,
        .aplStr = "system_core",
    };
    infoInstance.processName = "RegisterInputer";
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    AccessTokenKit::ReloadNativeTokenInfo();
    delete[] perms;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    NativeTokenGet();
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GetDomainAccountInfoFuzzTest(data, size);
    return 0;
}

