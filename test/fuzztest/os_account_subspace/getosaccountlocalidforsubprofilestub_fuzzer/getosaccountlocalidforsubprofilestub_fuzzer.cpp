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

#include "getosaccountlocalidforsubprofilestub_fuzzer.h"

#include <string>
#include <vector>

#include "access_token.h"
#include "accesstoken_kit.h"
#include "fuzz_data.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

#include "account_mgr_service.h"
#include "ohos_account_manager.h"

using namespace std;
using namespace OHOS::AccountSA;
using namespace OHOS::Security::AccessToken;

#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
namespace OHOS {
namespace AccountSA {
void OhosAccountManager::InitOsAccountSubProfileManager(const std::string &rootPath) {}

ErrCode OhosAccountManager::GetOsAccountLocalIdForSubProfile(
    int32_t subProfileId, int32_t &localId)
{
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS
#endif  // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE

namespace OHOS {
namespace {
const std::u16string ACCOUNT_TOKEN = u"ohos.accountfwk.IAccount";

bool WriteInterfaceTokenByStrategy(MessageParcel &data, uint8_t tokenStrategy)
{
    if (tokenStrategy == 0) {
        return true;
    }
    if (tokenStrategy == 1) {
        return data.WriteInterfaceToken(u"wrong.token");
    }
    return data.WriteInterfaceToken(ACCOUNT_TOKEN);
}
}

bool GetOsAccountLocalIdForSubProfileStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    FuzzData fuzzData(data, size);
    uint8_t tokenStrategy = fuzzData.GetData<uint8_t>();

    MessageParcel reply;
    MessageOption option;
    auto service = std::make_shared<AccountMgrService>();

    MessageParcel dataTemp;
    if (!WriteInterfaceTokenByStrategy(dataTemp, tokenStrategy)) {
        return false;
    }
    int32_t subProfileId = fuzzData.GetData<int32_t>();
    if (!dataTemp.WriteInt32(subProfileId)) {
        return false;
    }
    uint32_t code = static_cast<uint32_t>(IAccountIpcCode::COMMAND_GET_OS_ACCOUNT_LOCAL_ID_FOR_SUB_PROFILE);
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
    infoInstance.processName = "GetOsAccountLocalIdForSubProfileStubFuzzTest";
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    AccessTokenKit::ReloadNativeTokenInfo();
    delete[] perms;
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    NativeTokenGet();
    OhosAccountManager::GetInstance().OnInitialize();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::GetOsAccountLocalIdForSubProfileStubFuzzTest(data, size);
    return 0;
}
