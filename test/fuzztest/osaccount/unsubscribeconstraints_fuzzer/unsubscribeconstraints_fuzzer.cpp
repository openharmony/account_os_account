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

#include "unsubscribeconstraints_fuzzer.h"

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
#include "token_setproc.h"

using namespace std;
using namespace OHOS::AccountSA;
using namespace OHOS::Security::AccessToken;
class TestOsAccountConstraintSubscriber : public OsAccountConstraintSubscriber {
public:
    explicit TestOsAccountConstraintSubscriber(const std::set<std::string> &constraintSet)
        : OsAccountConstraintSubscriber(constraintSet) {}
    void OnConstraintChanged(const OsAccountConstraintStateData &constraintData) {}
};

namespace OHOS {
    bool UnsubscribeConstraintsFuzzTest(const uint8_t* data, size_t size)
    {
        int32_t result = ERR_OK;
        if ((data != nullptr) && (size != 0)) {
            FuzzData fuzzData(data, size);
            std::string testStr = fuzzData.GenerateString();
            std::set<string> constraints = {testStr};
            auto subscriber = std::make_shared<TestOsAccountConstraintSubscriber>(constraints);
            result = OsAccountManager::UnsubscribeOsAccountConstraints(subscriber);
        }
        return result == ERR_OK;
    }
}

void NativeTokenGet()
{
    uint64_t tokenId;
    const char **perms = new const char *[1];
    perms[0] = "ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS";
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
    OHOS::UnsubscribeConstraintsFuzzTest(data, size);
    return 0;
}

