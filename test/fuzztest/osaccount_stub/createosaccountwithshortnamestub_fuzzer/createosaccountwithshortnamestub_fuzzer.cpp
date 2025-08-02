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

#include "createosaccountwithshortnamestub_fuzzer.h"
#include "os_account_stub.h"
#include "account_log_wrapper.h"
#include "fuzz_data.h"
#include "os_account_manager_service.h"
#include <string>
#include <vector>

using namespace OHOS::AccountSA;

const std::u16string IOS_ACCOUNT_DESCRIPTOR = u"ohos.accountfwk.IOsAccount";
const int32_t OS_ACCOUNT_TYPE_NUM = 5;

namespace OHOS {
    bool CreateOsAccountWithShortNameStubFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }
        
        FuzzData fuzzData(data, size);
        MessageParcel dataParcel;
        if (!dataParcel.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR)) {
            return false;
        }
        
        // Write localName
        std::string localName = fuzzData.GenerateString();
        if (!dataParcel.WriteString(localName)) {
            return false;
        }
        
        // Write hasShortName
        bool hasShortName = true;
        if (!dataParcel.WriteBool(hasShortName)) {
            return false;
        }
        // Write shortName
        std::string shortName = fuzzData.GenerateString();
        if (!dataParcel.WriteString(shortName)) {
            return false;
        }
        
        // Write type
        int32_t typeValue = fuzzData.GetData<int32_t>() % OS_ACCOUNT_TYPE_NUM; // OsAccountType range
        if (!dataParcel.WriteInt32(typeValue)) {
            return false;
        }

        CreateOsAccountOptions options;
        if (!dataParcel.WriteParcelable(&options)) {
            return false;
        }
        
        MessageParcel reply;
        MessageOption option;
        auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
        osAccountManagerService_->OnRemoteRequest(static_cast<uint32_t>(IOsAccountIpcCode::
            COMMAND_CREATE_OS_ACCOUNT_IN_STRING_IN_STRING_IN_INT_OUT_STRINGRAWDATA),
            dataParcel, reply, option);
        osAccountManagerService_->OnRemoteRequest(static_cast<uint32_t>(IOsAccountIpcCode::
            COMMAND_CREATE_OS_ACCOUNT_IN_STRING_IN_STRING_IN_INT_OUT_STRINGRAWDATA_IN_CREATEOSACCOUNTOPTIONS),
            dataParcel, reply, option);

        return true;
    }

    void InitOsAccountWithShortname()
    {
        MessageParcel dataParcel;
        dataParcel.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR);
        dataParcel.WriteString("test_short_local_name");
        dataParcel.WriteBool(true);
        dataParcel.WriteString("test_short_short_name");
        dataParcel.WriteInt32(static_cast<int32_t>(OsAccountType::ADMIN));
        CreateOsAccountOptions options;
        dataParcel.WriteParcelable(&options);

        MessageParcel reply;
        MessageOption option;
        auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
        osAccountManagerService_->OnRemoteRequest(static_cast<uint32_t>(IOsAccountIpcCode::
            COMMAND_CREATE_OS_ACCOUNT_IN_STRING_IN_STRING_IN_INT_OUT_STRINGRAWDATA),
            dataParcel, reply, option);
        osAccountManagerService_->OnRemoteRequest(static_cast<uint32_t>(IOsAccountIpcCode::
            COMMAND_CREATE_OS_ACCOUNT_IN_STRING_IN_STRING_IN_INT_OUT_STRINGRAWDATA_IN_CREATEOSACCOUNTOPTIONS),
            dataParcel, reply, option);
    }
} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::InitOsAccountWithShortname();
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::CreateOsAccountWithShortNameStubFuzzTest(data, size);
    return 0;
}
