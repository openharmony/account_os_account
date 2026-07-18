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

#include "procauthuserwithunlockoptionsstub_fuzzer.h"

#include <string>
#include <vector>
#include "account_test_common.h"
#include "domain_account_callback_stub.h"
#include "domain_account_manager_service.h"
#include "fuzz_data.h"
#include "idomain_account.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const int32_t PASSWORD_LEN = 8;
const int32_t CHALLENGE_LEN = 4;
const uint32_t TEST_VECTOR_MAX_SIZE = 102402;
const int32_t ROOT_UID = 0;

class TestDomainAuthCallback : public DomainAccountCallbackStub {
public:
    TestDomainAuthCallback() {};
    virtual ~TestDomainAuthCallback() {};
    ErrCode OnResult(int32_t errCode, const DomainAccountParcel &parcel) override
    {
        return ERR_OK;
    }
    ErrCode OnAcquireInfo(int32_t module, uint32_t acquireInfo,
        const DomainAccountUnlockExtraInfoIdl &extraInfo) override
    {
        return ERR_OK;
    }
};

static uint64_t g_tokenID = 0;
static bool g_permissionReady = false;

static void InitPermission()
{
    if (g_permissionReady) {
        return;
    }
    g_permissionReady = true;
    setuid(ROOT_UID);
    OHOS::AccountSA::AllocPermission({"ohos.permission.ACCESS_USER_AUTH_INTERNAL"}, g_tokenID);
}
}

namespace OHOS {
    bool ProcAuthUserWithUnlockOptionsStubFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }
        InitPermission();

        FuzzData fuzzData(data, size);
        int32_t localId = fuzzData.GetData<int32_t>();

        auto callback = new (std::nothrow) TestDomainAuthCallback();

        MessageParcel dataTemp;
        if (!dataTemp.WriteInterfaceToken(DomainAccountStub::GetDescriptor())) {
            return false;
        }
        if (!dataTemp.WriteInt32(localId)) {
            return false;
        }
        uint32_t passwordSize = fuzzData.GetData<bool>() ? TEST_VECTOR_MAX_SIZE : PASSWORD_LEN;
        if (!dataTemp.WriteInt32(passwordSize)) {
            return false;
        }
        for (uint32_t i = 0; i < PASSWORD_LEN; i++) {
            if (!dataTemp.WriteUint8(fuzzData.GetData<uint8_t>())) {
                return false;
            }
        }
        uint32_t challengeSize = fuzzData.GetData<bool>() ? TEST_VECTOR_MAX_SIZE : CHALLENGE_LEN;
        if (!dataTemp.WriteInt32(challengeSize)) {
            return false;
        }
        for (uint32_t i = 0; i < CHALLENGE_LEN; i++) {
            if (!dataTemp.WriteUint8(fuzzData.GetData<uint8_t>())) {
                return false;
            }
        }
        if (!dataTemp.WriteInt32(fuzzData.GetData<int32_t>())) {
            return false;
        }
        if (fuzzData.GetData<bool>()) {
            if (callback != nullptr && !dataTemp.WriteRemoteObject(callback->AsObject())) {
                return false;
            }
        }

        MessageParcel reply;
        MessageOption option;
        uint32_t code = static_cast<uint32_t>(IDomainAccountIpcCode::COMMAND_AUTH_USER_WITH_UNLOCK_OPTIONS);
        auto domainAccountService = std::make_shared<DomainAccountManagerService>();
        domainAccountService->OnRemoteRequest(code, dataTemp, reply, option);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::ProcAuthUserWithUnlockOptionsStubFuzzTest(data, size);
    return 0;
}
