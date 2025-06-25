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

#include "prepareremoteauthstub_fuzzer.h"

#include <string>
#include <vector>
#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_kit.h"
#include "account_iam_callback_service.h"
#include "account_iam_service.h"
#include "account_log_wrapper.h"
#include "fuzz_data.h"
#include "account_i_a_m_stub.h"
#include "securec.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS::AccountSA;
using namespace OHOS::Security::AccessToken;
namespace OHOS {
const std::u16string IAMACCOUNT_TOKEN = u"ohos.accountfwk.IAccountIAM";

class PreRemoteAuthCallbackImpl : public PreRemoteAuthCallback {
public:
    virtual ~PreRemoteAuthCallbackImpl() = default;
    void OnResult(int32_t result) override
    {
        return;
    }
};

bool PrepareRemoteAuthStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    MessageParcel dataTemp;
    if (!dataTemp.WriteInterfaceToken(IAMACCOUNT_TOKEN)) {
        return false;
    }
    FuzzData fuzzData(data, size);
    std::string remoteNetworkId = fuzzData.GenerateString();
    if (!dataTemp.WriteString(remoteNetworkId)) {
        return false;
    }
    auto callback = std::make_shared<PreRemoteAuthCallbackImpl>();
    sptr<IPreRemoteAuthCallback> wrapper = new (std::nothrow) PreRemoteAuthCallbackService(callback);
    if (!dataTemp.WriteRemoteObject(wrapper->AsObject())) {
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(IAccountIAMIpcCode::COMMAND_PREPARE_REMOTE_AUTH);
    auto iamAccountManagerService = std::make_shared<AccountIAMService>();
    iamAccountManagerService->OnRemoteRequest(code, dataTemp, reply, option);

    return true;
}
} // namespace OHOS

void NativeTokenGet()
{
    uint64_t tokenId;
    const char **perms = new const char *[1];
    perms[0] = "ohos.permission.ACCESS_USER_AUTH_INTERNAL";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 1,
        .aclsNum = 0,
        .perms = perms,
        .acls = nullptr,
        .aplStr = "system_core",
    };
    infoInstance.processName = "PrepareRemoteAuth";
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
    OHOS::PrepareRemoteAuthStubFuzzTest(data, size);
    return 0;
}
