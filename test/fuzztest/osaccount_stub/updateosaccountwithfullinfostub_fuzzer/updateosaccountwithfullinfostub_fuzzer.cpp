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

#include "updateosaccountwithfullinfostub_fuzzer.h"
#include "os_account_stub.h"
#include "account_log_wrapper.h"
#include "fuzz_data.h"
#include "os_account_manager_service.h"
#include <string>
#include <vector>

using namespace OHOS::AccountSA;

const int32_t MAX_TEST_ID = 10738; // Maximum test
const int32_t OS_ACCOUNT_TYPE_NUM = 5;
const std::u16string IOS_ACCOUNT_DESCRIPTOR = u"ohos.accountfwk.IOsAccount";

namespace OHOS {
    bool UpdateOsAccountWithFullInfoStubFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }
        
        FuzzData fuzzData(data, size);
        MessageParcel dataParcel;
        auto useValidDescriptor = fuzzData.GenerateBool();
        if (useValidDescriptor) {
            if (!dataParcel.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR)) {
                return false;
            }
        }
        auto useOsAccountInfo = fuzzData.GenerateBool();
        if (useOsAccountInfo) {
            // Create OsAccountInfo object for fuzzing
            OsAccountInfo osAccountInfo;
            int32_t localId = fuzzData.GetData<bool>() ?
                            (fuzzData.GetData<int32_t>() % MAX_TEST_ID) : fuzzData.GetData<int32_t>();
            osAccountInfo.SetLocalId(localId);
            osAccountInfo.SetLocalName(fuzzData.GenerateString());
            osAccountInfo.SetShortName(fuzzData.GenerateString());
            osAccountInfo.SetType(static_cast<OsAccountType>(fuzzData.GetData<int32_t>() % OS_ACCOUNT_TYPE_NUM));
            osAccountInfo.SetIsCreateCompleted(fuzzData.GetData<bool>());
            osAccountInfo.SetIsActived(fuzzData.GetData<bool>());
            
            if (!dataParcel.WriteParcelable(&osAccountInfo)) {
                return false;
            }
        }

        MessageParcel reply;
        MessageOption option;
        auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
        osAccountManagerService_->OnRemoteRequest(
            static_cast<uint32_t>(IOsAccountIpcCode::COMMAND_UPDATE_OS_ACCOUNT_WITH_FULL_INFO),
            dataParcel, reply, option);

        return true;
    }
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::UpdateOsAccountWithFullInfoStubFuzzTest(data, size);
    return 0;
}
