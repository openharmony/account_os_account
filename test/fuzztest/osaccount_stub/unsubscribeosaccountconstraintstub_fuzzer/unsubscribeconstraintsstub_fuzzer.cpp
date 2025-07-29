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

#include "unsubscribeconstraintsstub_fuzzer.h"
#include <string>
#include <thread>
#include <vector>
#include "accesstoken_kit.h"
#include "fuzz_data.h"
#include "ios_account.h"
#include "os_account_constraint_subscriber_manager.h"
#include "os_account_manager_service.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS::AccountSA;
using namespace OHOS::Security::AccessToken;
namespace OHOS {
const std::u16string IOS_ACCOUNT_DESCRIPTOR = u"ohos.accountfwk.IOsAccount";
const std::string TEST_CONSTRIANT = "constraint.wifi";

bool SubscribeOsAccountConstraint(const std::string &constraint)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR);
    std::set<string> constraints = {constraint};
    OsAccountConstraintSubscribeInfo subscriber(constraints);
    if (!datas.WriteParcelable(&subscriber)) {
        return false;
    }

    if (!datas.WriteRemoteObject(OsAccountConstraintSubscriberManager::GetInstance()->AsObject())) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();

    osAccountManagerService_ ->OnRemoteRequest(
        static_cast<int32_t>(IOsAccountIpcCode::COMMAND_SUBSCRIBE_OS_ACCOUNT_CONSTRAINTS), datas, reply, option);

    return true;
}

bool UnsubscribeOsAccountConstraintStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzData fuzzData(data, size);
    std::string testStr = fuzzData.GetData<bool>() ? fuzzData.GenerateString() : TEST_CONSTRIANT;
    SubscribeOsAccountConstraint(testStr);

    int32_t id = fuzzData.GetData<int32_t>();
    OsAccountConstraintSubscribeManager::GetInstance().Publish(id, {testStr}, fuzzData.GetData<bool>());
    MessageParcel datas;
    datas.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR);
    std::set<string> constraints = {testStr};
    OsAccountConstraintSubscribeInfo subscriber(constraints);

    if (!datas.WriteParcelable(&subscriber)) {
        return false;
    }

    if (!datas.WriteRemoteObject(OsAccountConstraintSubscriberManager::GetInstance()->AsObject())) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();

    osAccountManagerService_ ->OnRemoteRequest(
        static_cast<int32_t>(IOsAccountIpcCode::COMMAND_UNSUBSCRIBE_OS_ACCOUNT_CONSTRAINTS), datas, reply, option);

    return true;
}
} // namespace OHOS

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
    infoInstance.processName = "UNSUBSCRIBE_OSACCOUNT_CONSTRAINT";
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    AccessTokenKit::ReloadNativeTokenInfo();
    delete [] perms;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    NativeTokenGet();
    return 0;
}


/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::UnsubscribeOsAccountConstraintStubFuzzTest(data, size);
    return 0;
}
