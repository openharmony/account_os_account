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

#include "createosaccountwithfullinfo_fuzzer.h"

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
#include "os_account_manager_service.h"
#include "os_account_proxy.h"
#include "securec.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS::AccountSA;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
constexpr int32_t START_USER_ID_100 = 100;
constexpr int64_t TEST_TIMESTAMP_2022 = 1640995200;

int32_t GetUserId(FuzzData& fuzzData, bool useValid, int32_t defaultId)
{
    return useValid ? defaultId : fuzzData.GetData<int32_t>();
}

int64_t GetTimestamp(FuzzData& fuzzData, bool useValid, int64_t defaultTime = TEST_TIMESTAMP_2022)
{
    return useValid ? defaultTime : fuzzData.GetData<int64_t>();
}

bool CreateOsAccountWithFullInfoFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzData fuzzData(data, size);
    bool useValidParams = fuzzData.GetData<bool>();
    
    OsAccountInfo osAccountInfo;
    osAccountInfo.SetLocalName(fuzzData.GenerateString());
    osAccountInfo.SetLocalId(START_USER_ID_100);
    osAccountInfo.SetSerialNumber(GetUserId(fuzzData, useValidParams, START_USER_ID_100));
    osAccountInfo.SetCreateTime(GetTimestamp(fuzzData, useValidParams));
    osAccountInfo.SetLastLoginTime(GetTimestamp(fuzzData, useValidParams));
    
    int32_t result = OsAccountManager::CreateOsAccountWithFullInfo(osAccountInfo);
    if (result == ERR_OK) {
        ACCOUNT_LOGI("CreateOsAccountWithFullInfoFuzzTest RemoveOsAccount");
        OsAccountManager::RemoveOsAccount(osAccountInfo.GetLocalId());
    }
    auto servicePtr = new (std::nothrow) OsAccountManagerService();
    std::shared_ptr<OsAccountProxy> osAccountProxy = std::make_shared<OsAccountProxy>(servicePtr->AsObject());
    result = osAccountProxy->CreateOsAccountWithFullInfo(osAccountInfo);
    if (result == ERR_OK) {
        ACCOUNT_LOGI("CreateOsAccountWithFullInfoFuzzTest RemoveOsAccount");
        OsAccountManager::RemoveOsAccount(osAccountInfo.GetLocalId());
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
    OHOS::CreateOsAccountWithFullInfoFuzzTest(data, size);
    return 0;
}
