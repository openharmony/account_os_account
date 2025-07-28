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

#include "updateaccountinfo_fuzzer.h"

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

namespace {
constexpr int32_t PERMISSION_COUNT_NUM = 2;
constexpr int32_t FIRST_PARAM_INDEX = 0;
constexpr int32_t SECOND_PARAM_INDEX = 1;
}

namespace OHOS {
namespace {
const int ENUM_MAX = 4;
}
bool UpdateAccountInfoFuzzTest(const uint8_t* data, size_t size)
{
    bool result = false;
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    FuzzData fuzzData(data, size);
    DomainAccountInfo oldAccountInfo;
    oldAccountInfo.domain_ = fuzzData.GenerateString();
    oldAccountInfo.accountName_ = fuzzData.GenerateString();
    oldAccountInfo.accountId_ = fuzzData.GenerateString();
    oldAccountInfo.isAuthenticated = fuzzData.GenerateBool();
    oldAccountInfo.serverConfigId_ = fuzzData.GenerateString();
    int typeNumber = fuzzData.GetData<int>() % ENUM_MAX;
    oldAccountInfo.status_ = static_cast<DomainAccountStatus>(typeNumber);

    DomainAccountInfo newAccountInfo;
    newAccountInfo.domain_ = fuzzData.GenerateString();
    newAccountInfo.accountName_ = fuzzData.GenerateString();
    newAccountInfo.accountId_ = fuzzData.GenerateString();
    newAccountInfo.isAuthenticated = fuzzData.GenerateBool();
    newAccountInfo.serverConfigId_ = fuzzData.GenerateString();
    typeNumber = fuzzData.GetData<int>() % ENUM_MAX;
    newAccountInfo.status_ = static_cast<DomainAccountStatus>(typeNumber);

    result = DomainAccountClient::GetInstance().UpdateAccountInfo(oldAccountInfo, newAccountInfo);
    return result == ERR_OK;
}
}

void NativeTokenGet()
{
    uint64_t tokenId;
    const char **perms = new const char *[PERMISSION_COUNT_NUM];
    perms[FIRST_PARAM_INDEX] = "ohos.permission.MANAGE_LOCAL_ACCOUNTS";
    perms[SECOND_PARAM_INDEX] = "ohos.permission.MANAGE_DOMAIN_ACCOUNTS";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = PERMISSION_COUNT_NUM,
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
    OHOS::UpdateAccountInfoFuzzTest(data, size);
    return 0;
}

