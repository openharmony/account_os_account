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

#include "authuserstub_fuzzer.h"
#include <string>
#include <vector>
#include "account_log_wrapper.h"
#include "account_iam_service.h"
#include "account_iam_client.h"
#include "account_iam_callback_service.h"
#include "iaccount_iam.h"

using namespace std;
using namespace OHOS::AccountSA;
namespace OHOS {
const std::u16string IAMACCOUNT_TOKEN = u"ohos.accountfwk.IAccountIAM";

class MockIDMCallback : public OHOS::AccountSA::IDMCallback {
public:
    virtual ~MockIDMCallback()
    {
    }
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) override
    {
        return;
    }
    void OnResult(int32_t result, const Attributes &extraInfo) override
    {
        return;
    }
};

bool AuthUserStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    int32_t userId = static_cast<int32_t>(size);
    std::vector<uint8_t> challenge = {static_cast<uint8_t>(size)};
    AuthType authType = static_cast<AuthType>(size);
    AuthTrustLevel authTrustLevel = static_cast<AuthTrustLevel>(size);
    std::shared_ptr<IDMCallback> ptr = make_shared<MockIDMCallback>();
    sptr<IIDMCallback> callback = new (std::nothrow) IDMCallbackService(userId, ptr);

    MessageParcel dataTemp;
    if (!dataTemp.WriteInterfaceToken(IAMACCOUNT_TOKEN)) {
        return false;
    }

    if (!dataTemp.WriteInt32(userId)) {
        return false;
    }

    if (!dataTemp.WriteUInt8Vector(challenge)) {
        return false;
    }
    if (!dataTemp.WriteInt32(authType)) {
        return false;
    }
    if (!dataTemp.WriteUint32(authTrustLevel)) {
        return false;
    }
    if (!dataTemp.WriteRemoteObject(callback->AsObject())) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(AccountIAMInterfaceCode::AUTH_USER);
    auto iamAccountManagerService = std::make_shared<AccountIAMService>();
    iamAccountManagerService->OnRemoteRequest(code, dataTemp, reply, option);

    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::AuthUserStubFuzzTest(data, size);
    return 0;
}
