/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "unsubscribedistributedaccountspaceeventsstub_fuzzer.h"

#include <cstdint>
#include <string>
#include <vector>
#define private public
#include "account_mgr_service.h"
#undef private
#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_kit.h"
#include "account_info.h"
#include "account_log_wrapper.h"
#include "distributed_account_event_service.h"
#include "nativetoken_kit.h"
#include "fuzz_data.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS::AccountSA;
using namespace OHOS::Security::AccessToken;

const std::u16string OHOS_ACCOUNT_DESCRIPTOR = u"ohos.accountfwk.IAccount";
const int32_t ENUM_SIZE = 4;
namespace OHOS {
bool UnsubscribeDistributedAccountSpaceEventsStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(OHOS_ACCOUNT_DESCRIPTOR);
    FuzzData fuzzData(data, size);
    std::vector<int32_t> typeInts;
    int32_t typeCount = fuzzData.GetData<int32_t>() % ENUM_SIZE + 1;
    for (int32_t i = 0; i < typeCount && i < ENUM_SIZE; i++) {
        int32_t type = fuzzData.GetData<int32_t>() % ENUM_SIZE;
        typeInts.push_back(type);
    }
    if (!datas.WriteInt32Vector(typeInts)) {
        return false;
    }
    if (fuzzData.GenerateBool()) {
        if (!datas.WriteRemoteObject(DistributedAccountEventService::GetInstance()->AsObject())) {
            return false;
        }
    }
    MessageParcel reply;
    MessageOption option;
    auto accountManagerService = std::make_shared<AccountMgrService>();
    accountManagerService->state_ = STATE_RUNNING;
    accountManagerService->OnRemoteRequest(
        static_cast<int32_t>(IAccountIpcCode::COMMAND_UNSUBSCRIBE_DISTRIBUTED_ACCOUNT_SPACE_EVENTS),
        datas, reply, option);
    return true;
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
    infoInstance.processName = "UNSUBSCRIBE_OSACCOUNT_SPACE";
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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::UnsubscribeDistributedAccountSpaceEventsStubFuzzTest(data, size);
    return 0;
}