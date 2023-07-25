/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "getavailablestatusstub_fuzzer.h"
#include <string>
#include <vector>

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_kit.h"
#include "account_iam_service.h"
#include "account_log_wrapper.h"
#include "iaccount_iam.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS::AccountSA;
using namespace OHOS::Security::AccessToken;
namespace OHOS {
const std::u16string IAMACCOUNT_TOKEN = u"ohos.accountfwk.IAccountIAM";

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
    infoInstance.processName = "GET_AVAILABLE_STATUS";
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    AccessTokenKit::ReloadNativeTokenInfo();
    delete [] perms;
}

bool GetAvailableStatusStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    AuthType authType = static_cast<AuthType>(size);
    AuthTrustLevel authTrustLevel = static_cast<AuthTrustLevel>(size);

    MessageParcel dataTemp;
    if (!dataTemp.WriteInterfaceToken(IAMACCOUNT_TOKEN)) {
        return false;
    }

    if (!dataTemp.WriteInt32(authType)) {
        return false;
    }
    if (!dataTemp.WriteUint32(authTrustLevel)) {
        return false;
    }

    NativeTokenGet();

    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(AccountIAMInterfaceCode::GET_AVAILABLE_STATUS);
    auto iamAccountManagerService = std::make_shared<AccountIAMService>();
    iamAccountManagerService->OnRemoteRequest(code, dataTemp, reply, option);

    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::GetAvailableStatusStubFuzzTest(data, size);
    return 0;
}
