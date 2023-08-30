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

#include "cmdqueryohosaccountinfobyuseridstub_fuzzer.h"

#include <string>
#include <vector>
#include "src/callbacks.h"

#define private public
#include "account_mgr_service.h"
#undef private
#include "iaccount.h"

using namespace std;
using namespace OHOS::AccountSA;

namespace OHOS {
namespace {
const std::u16string ACCOUNT_TOKEN = u"ohos.accountfwk.IAccount";
static pthread_once_t g_fcOnce = PTHREAD_ONCE_INIT;
}

static int SelinuxLog(int logLevel, const char *fmt, ...)
{
    (void)logLevel;
    (void)fmt;
    return 0;
}

static void SelinuxSetCallback()
{
    union selinux_callback cb;
    cb.func_log = SelinuxLog;
    selinux_set_callback(SELINUX_CB_LOG, cb);
}

bool CmdQueryOhosAccountInfoByUserIdStubFuzzTest(const uint8_t* data, size_t size)
{
    __selinux_once(g_fcOnce, SelinuxSetCallback);
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    MessageParcel dataTemp;
    int32_t userId = static_cast<int32_t>(size);
    if (!dataTemp.WriteInterfaceToken(ACCOUNT_TOKEN)) {
        return false;
    }
    if (!dataTemp.WriteInt32(userId)) {
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(AccountMgrInterfaceCode::QUERY_OHOS_ACCOUNT_INFO_BY_USER_ID);
    DelayedRefSingleton<AccountMgrService>::GetInstance().state_ = ServiceRunningState::STATE_RUNNING;
    DelayedRefSingleton<AccountMgrService>::GetInstance().OnRemoteRequest(code, dataTemp, reply, option);

    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::CmdQueryOhosAccountInfoByUserIdStubFuzzTest(data, size);
    return 0;
}

