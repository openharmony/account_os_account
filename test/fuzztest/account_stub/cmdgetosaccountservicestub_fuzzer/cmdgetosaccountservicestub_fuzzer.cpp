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

#include "cmdgetosaccountservicestub_fuzzer.h"

#include <string>
#include <vector>
#define private public
#include "account_mgr_service.h"
#undef private
#include "fuzz_data.h"
#include "iaccount.h"

using namespace std;
using namespace OHOS::AccountSA;

namespace OHOS {
namespace {
const std::u16string ACCOUNT_TOKEN = u"ohos.accountfwk.IAccount";
constexpr size_t MAX_RANDOM_STRING_LENGTH = 64;
constexpr size_t MIN_RANDOM_STRING_LENGTH = 1;
constexpr char16_t NULL_CHARACTER = 0;
constexpr char16_t ASCII_MAX = 0x007F;
constexpr char16_t PRINTABLE_ASCII_COUNT = 95;
constexpr char16_t SPACE_CHARACTER = 32;

std::u16string GenerateRandomU16String(FuzzData& fuzzData)
{
    size_t length = (fuzzData.GetData<uint8_t>() % MAX_RANDOM_STRING_LENGTH) + MIN_RANDOM_STRING_LENGTH;
    std::u16string result;
    result.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        char16_t ch = fuzzData.GetData<char16_t>();
        if (ch == NULL_CHARACTER || ch > ASCII_MAX) {
            ch = static_cast<char16_t>((ch % PRINTABLE_ASCII_COUNT) + SPACE_CHARACTER);
        }
        result.push_back(ch);
    }
    return result;
}
}

bool CmdGetOsAccountServiceStubFuzzTest(const uint8_t* data, size_t size, uint32_t code)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    
    FuzzData fuzzData(data, size);
    MessageParcel dataTemp;
    
    uint8_t randomByte = fuzzData.GetData<uint8_t>();
    bool useValidToken = (randomByte & 0x01) != 0;
    bool useRunningState = (randomByte & 0x02) != 0;

    std::u16string token = useValidToken ? ACCOUNT_TOKEN : GenerateRandomU16String(fuzzData);
    if (!dataTemp.WriteInterfaceToken(token)) {
        return false;
    }
    
    std::string randomStr = fuzzData.GenerateString();
    dataTemp.WriteString(randomStr);
    
    int32_t randomInt = fuzzData.GetData<int32_t>();
    dataTemp.WriteInt32(randomInt);

    ServiceRunningState state = useRunningState ?
                               ServiceRunningState::STATE_RUNNING :
                               ServiceRunningState::STATE_NOT_START;
    DelayedRefSingleton<AccountMgrService>::GetInstance().state_ = state;
    
    MessageParcel reply;
    MessageOption option;
    DelayedRefSingleton<AccountMgrService>::GetInstance().OnRemoteRequest(code, dataTemp, reply, option);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::CmdGetOsAccountServiceStubFuzzTest(
        data, size, static_cast<uint32_t>(IAccountIpcCode::COMMAND_GET_OS_ACCOUNT_SERVICE));
    OHOS::CmdGetOsAccountServiceStubFuzzTest(
        data, size, static_cast<uint32_t>(IAccountIpcCode::COMMAND_GET_APP_ACCOUNT_SERVICE));
    OHOS::CmdGetOsAccountServiceStubFuzzTest(
        data, size, static_cast<uint32_t>(IAccountIpcCode::COMMAND_GET_ACCOUNT_I_A_M_SERVICE));
    OHOS::CmdGetOsAccountServiceStubFuzzTest(
        data, size, static_cast<uint32_t>(IAccountIpcCode::COMMAND_GET_DOMAIN_ACCOUNT_SERVICE));
    return 0;
}