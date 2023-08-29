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

#include "cmdsetohosaccountinfostub_fuzzer.h"

#include <string>
#include <vector>

#define private public
#include "account_mgr_service.h"
#undef private
#include "iaccount.h"

using namespace std;
using namespace OHOS::AccountSA;

namespace OHOS {
namespace {
const std::u16string ACCOUNT_TOKEN = u"ohos.accountfwk.IAccount";
}
bool CmdSetOhosAccountInfoStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    MessageParcel dataTemp;
    if (!dataTemp.WriteInterfaceToken(ACCOUNT_TOKEN)) {
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(AccountMgrInterfaceCode::SET_OHOS_ACCOUNT_INFO);
    DelayedRefSingleton<AccountMgrService>::GetInstance().state_ = ServiceRunningState::STATE_RUNNING;
    DelayedRefSingleton<AccountMgrService>::GetInstance().OnRemoteRequest(code, dataTemp, reply, option);

    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::CmdSetOhosAccountInfoStubFuzzTest(data, size);
    return 0;
}

