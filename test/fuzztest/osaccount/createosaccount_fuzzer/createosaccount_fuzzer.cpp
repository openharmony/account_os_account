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

#include "createosaccount_fuzzer.h"

#include <cstdint>
#include <string>
#include <vector>

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_kit.h"
#include "account_log_wrapper.h"
#include "fuzz_data.h"
#include "nativetoken_kit.h"
#include "os_account_constants.h"
#include "os_account_manager.h"
#include "securec.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS::AccountSA;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
constexpr uint32_t MAX_ACCOUNT_TYPE_COUNT = 5;

OsAccountType GetAccountType(FuzzData& fuzzData, bool useValid)
{
    if (useValid) {
        return OsAccountType::NORMAL;
    }
    return static_cast<OsAccountType>(fuzzData.GetData<uint32_t>() % MAX_ACCOUNT_TYPE_COUNT);
}

bool CreateOsAccountFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzData fuzzData(data, size);
    bool useValidParams = fuzzData.GetData<bool>();
    
    OsAccountInfo osAccountInfoOne;
    OsAccountType testType = GetAccountType(fuzzData, useValidParams);
    std::string accountName = fuzzData.GenerateString();
    
    int32_t result = OsAccountManager::CreateOsAccount(accountName, testType, osAccountInfoOne);
    if (result == ERR_OK) {
        ACCOUNT_LOGI("CreateOsAccountFuzzTest RemoveOsAccount");
        OsAccountManager::RemoveOsAccount(osAccountInfoOne.GetLocalId());
    }

    return result == ERR_OK;
}

} // namespace OHOS

void NativeTokenGet()
{
    uint64_t tokenId;
    const char **perms = new const char *[1];
    perms[0] = "ohos.permission.MANAGE_LOCAL_ACCOUNTS";
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
    OHOS::CreateOsAccountFuzzTest(data, size);
    return 0;
}