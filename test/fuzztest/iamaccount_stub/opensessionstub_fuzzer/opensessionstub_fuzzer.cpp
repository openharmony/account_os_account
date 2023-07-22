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

#include "opensessionstub_fuzzer.h"
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
    
    perms[0] = "ohos.permission.MANAGE_USER_IDM";

    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 1,
        .aclsNum = 0,
        .perms = perms,
        .acls = nullptr,
        .aplStr = "system_core",
    };
    infoInstance.processName = "OPEN_SESSION";
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    AccessTokenKit::ReloadNativeTokenInfo();
    delete [] perms;
}

bool OpenSessionStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    MessageParcel dataTemp;
    if (!dataTemp.WriteInterfaceToken(IAMACCOUNT_TOKEN)) {
        return false;
    }

    int32_t userId = size;
    if (!dataTemp.WriteInt32(userId)) {
        return false;
    }

    NativeTokenGet();

    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(AccountIAMInterfaceCode::OPEN_SESSION);
    auto iamAccountManagerService = std::make_shared<AccountIAMService>();
    iamAccountManagerService->OnRemoteRequest(code, dataTemp, reply, option);

    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::OpenSessionStubFuzzTest(data, size);
    return 0;
}
