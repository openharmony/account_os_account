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

#include "procsetdomainauthunlockenabledstub_fuzzer.h"

#include <string>
#include <vector>
#include "account_iam_service.h"
#include "account_test_common.h"
#include "fuzz_data.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const int32_t TOKEN_LEN = 8;
const int32_t SECRET_LEN = 8;
const uint32_t TEST_VECTOR_MAX_SIZE = 102402;
const int32_t ROOT_UID = 0;

static uint64_t g_tokenID = 0;
static bool g_permissionReady = false;

static void InitPermission()
{
    if (g_permissionReady) {
        return;
    }
    g_permissionReady = true;
    setuid(ROOT_UID);
    OHOS::AccountSA::AllocPermission({"ohos.permission.MANAGE_USER_IDM"}, g_tokenID);
}
}

namespace OHOS {
    bool ProcSetDomainAuthUnlockEnabledStubFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }
        InitPermission();

        FuzzData fuzzData(data, size);

        MessageParcel dataTemp;
        if (!dataTemp.WriteInterfaceToken(AccountIAMStub::GetDescriptor())) {
            return false;
        }
        if (!dataTemp.WriteInt32(fuzzData.GetData<int32_t>())) {
            return false;
        }
        uint32_t tokenSize = fuzzData.GetData<bool>() ? TEST_VECTOR_MAX_SIZE : TOKEN_LEN;
        if (!dataTemp.WriteInt32(tokenSize)) {
            return false;
        }
        for (uint32_t i = 0; i < TOKEN_LEN; i++) {
            if (!dataTemp.WriteUint8(fuzzData.GetData<uint8_t>())) {
                return false;
            }
        }
        uint32_t secretSize = fuzzData.GetData<bool>() ? TEST_VECTOR_MAX_SIZE : SECRET_LEN;
        if (!dataTemp.WriteInt32(secretSize)) {
            return false;
        }
        for (uint32_t i = 0; i < SECRET_LEN; i++) {
            if (!dataTemp.WriteUint8(fuzzData.GetData<uint8_t>())) {
                return false;
            }
        }
        if (!dataTemp.WriteInt32(fuzzData.GetData<int32_t>())) {
            return false;
        }

        MessageParcel reply;
        MessageOption option;
        uint32_t code = static_cast<uint32_t>(IAccountIAMIpcCode::COMMAND_SET_DOMAIN_AUTH_UNLOCK_ENABLED);
        auto iamService = std::make_shared<AccountIAMService>();
        iamService->OnRemoteRequest(code, dataTemp, reply, option);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::ProcSetDomainAuthUnlockEnabledStubFuzzTest(data, size);
    return 0;
}
