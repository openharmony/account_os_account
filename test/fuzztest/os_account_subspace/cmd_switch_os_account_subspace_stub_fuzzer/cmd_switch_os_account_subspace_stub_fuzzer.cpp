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

#include "cmd_switch_os_account_subspace_stub_fuzzer.h"

#include <string>
#include <vector>

#include "access_token.h"
#include "accesstoken_kit.h"
#include "fuzz_data.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

#define private public
#include "account_mgr_service.h"
#include "ohos_account_manager.h"
#include "os_account_subspace_manager_service.h"
#undef private

#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
namespace OHOS {
namespace AccountSA {
void OhosAccountManager::InitOsAccountSubProfileManager(const std::string &rootPath) {}

ErrCode OhosAccountManager::CreateOsAccountSubspace(int32_t osAccountId, OsAccountSubspaceResult &result)
{
    return ERR_OK;
}

ErrCode OhosAccountManager::DeleteOsAccountSubspace(int32_t osAccountId, int32_t subspaceId)
{
    return ERR_OK;
}

ErrCode OhosAccountManager::SwitchOsAccountSubspace(int32_t osAccountId, int32_t subspaceId, int32_t &fromSubspaceId)
{
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS
#endif  // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE

using namespace std;
using namespace OHOS::AccountSA;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace {
const std::u16string SUBSPACE_TOKEN = u"ohos.accountfwk.IOsAccountSubProfile";
}

bool CmdSwitchOsAccountSubspaceStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    MessageParcel dataTemp;
    FuzzData fuzzData(data, size);

    uint8_t tokenStrategy = fuzzData.GetData<uint8_t>();
    if (tokenStrategy == 0) {
    } else if (tokenStrategy == 1) {
        if (!dataTemp.WriteInterfaceToken(u"wrong.token")) {
            return false;
        }
    } else {
        if (!dataTemp.WriteInterfaceToken(SUBSPACE_TOKEN)) {
            return false;
        }
    }

    int32_t osAccountId = fuzzData.GetData<int32_t>();
    if (!dataTemp.WriteInt32(osAccountId)) {
        return false;
    }
    int32_t subspaceId = fuzzData.GetData<int32_t>();
    if (!dataTemp.WriteInt32(subspaceId)) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;

    auto service = std::make_shared<OsAccountSubProfileManagerService>();
    uint32_t code = static_cast<uint32_t>(IOsAccountSubProfileIpcCode::COMMAND_SWITCH_OS_ACCOUNT_SUB_PROFILE);
    service->OnRemoteRequest(code, dataTemp, reply, option);

    return true;
}
}

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
    infoInstance.processName = "CmdSwitchOsAccountSubspaceStub";
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    AccessTokenKit::ReloadNativeTokenInfo();
    delete[] perms;
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    NativeTokenGet();
    OhosAccountManager::GetInstance().OnInitialize();
    OHOS::DelayedRefSingleton<AccountMgrService>::GetInstance().state_ = ServiceRunningState::STATE_RUNNING;
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::CmdSwitchOsAccountSubspaceStubFuzzTest(data, size);
    return 0;
}
