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

#include "createosaccountwithfullinfostub_fuzzer.h"
#include "os_account_stub.h"
#include "account_log_wrapper.h"
#include "fuzz_data.h"
#include "os_account_manager_service.h"
#include <string>
#include <vector>

using namespace OHOS::AccountSA;

const int32_t TEST_USER_ID = 1006;
const int32_t OS_ACCOUNT_TYPE_NUM = 5;
const int64_t TEST_TIME_STAMP = 1695883215000;
const std::u16string IOS_ACCOUNT_DESCRIPTOR = u"ohos.accountfwk.IOsAccount";
const std::string TEST_HAP_STRING = "test_hap1";

namespace OHOS {
    bool CreateOsAccountWithFullInfoStubFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }
        
        FuzzData fuzzData(data, size);
        MessageParcel dataParcel;
        if (!dataParcel.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR)) {
            return false;
        }
        
        auto useOsAccountInfo = fuzzData.GenerateBool();
        if (useOsAccountInfo) {
            // Create OsAccountInfo object for fuzzing
            OsAccountInfo osAccountInfo;
            osAccountInfo.SetLocalId(fuzzData.GetData<int32_t>());
            osAccountInfo.SetLocalName(fuzzData.GenerateString());
            osAccountInfo.SetShortName(fuzzData.GenerateString());
            osAccountInfo.SetType(static_cast<OsAccountType>(fuzzData.GetData<int32_t>() % OS_ACCOUNT_TYPE_NUM));
            osAccountInfo.SetCreateTime(TEST_TIME_STAMP);
            osAccountInfo.SetLastLoginTime(TEST_TIME_STAMP);
            
            if (!dataParcel.WriteParcelable(&osAccountInfo)) {
                return false;
            }
        }

        auto useOptions = fuzzData.GenerateBool();
        if (useOptions) {
            CreateOsAccountOptions options;
            options.disallowedHapList.push_back(TEST_HAP_STRING);
            if (!options.allowedHapList.has_value()) {
                options.allowedHapList = std::vector<std::string>();
                options.allowedHapList->push_back(TEST_HAP_STRING);
            }
            if (!dataParcel.WriteParcelable(&options)) {
                return false;
            }
        }

        MessageParcel reply;
        MessageOption option;
        auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
        osAccountManagerService_->OnRemoteRequest(
            static_cast<uint32_t>(IOsAccountIpcCode::COMMAND_CREATE_OS_ACCOUNT_WITH_FULL_INFO),
            dataParcel, reply, option);
        osAccountManagerService_->OnRemoteRequest(
            static_cast<uint32_t>(IOsAccountIpcCode::COMMAND_CREATE_OS_ACCOUNT_WITH_FULL_INFO_IN_OSACCOUNTINFO),
            dataParcel, reply, option);
        return true;
    }

    void SetProfilePhoto()
    {
        MessageParcel datas;
        datas.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR);
        datas.WriteInt32(TEST_USER_ID);
        string photo = "test profile photo";
        StringRawData stringRawData;
        stringRawData.Marshalling(photo);
        datas.WriteUint32(stringRawData.size);
        datas.WriteRawData(stringRawData.data, stringRawData.size);
        MessageParcel reply;
        MessageOption option;
        auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();

        osAccountManagerService_->OnRemoteRequest(
            static_cast<int32_t>(IOsAccountIpcCode::COMMAND_SET_OS_ACCOUNT_PROFILE_PHOTO), datas, reply, option);
    }

    void CleanOsAccount()
    {
        MessageParcel data;
        MessageParcel reply;
        MessageOption option;
        data.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR);
        data.WriteInt32(TEST_USER_ID);

        auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
        osAccountManagerService_->OnRemoteRequest(
            static_cast<uint32_t>(IOsAccountIpcCode::COMMAND_IS_OS_ACCOUNT_DEACTIVATING),
            data, reply, option);
        MessageParcel datas;
        datas.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR);
        datas.WriteInt32(TEST_USER_ID);
        osAccountManagerService_->OnRemoteRequest(
            static_cast<uint32_t>(IOsAccountIpcCode::COMMAND_REMOVE_OS_ACCOUNT),
            datas, reply, option);
    }

    void UpdateOsAccountWithFullInfo()
    {
        MessageParcel dataParcel;
        dataParcel.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR);
        OsAccountInfo osAccountInfo;
        osAccountInfo.SetLocalId(TEST_USER_ID);
        osAccountInfo.SetLocalName("test_full_info_name");
        osAccountInfo.SetShortName("test_full_info_short_name");
        osAccountInfo.SetType(OsAccountType::NORMAL);
        osAccountInfo.SetCreateTime(TEST_TIME_STAMP);
        osAccountInfo.SetLastLoginTime(TEST_TIME_STAMP);
        dataParcel.WriteParcelable(&osAccountInfo);

        MessageParcel reply;
        MessageOption option;
        auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
        osAccountManagerService_->OnRemoteRequest(
            static_cast<uint32_t>(IOsAccountIpcCode::COMMAND_UPDATE_OS_ACCOUNT_WITH_FULL_INFO),
            dataParcel, reply, option);
    }

    void InitOsAccountWithFullInfo()
    {
        MessageParcel dataParcel;
        dataParcel.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR);
        OsAccountInfo osAccountInfo;
        osAccountInfo.SetLocalId(TEST_USER_ID);
        osAccountInfo.SetLocalName("test_full_info_name");
        osAccountInfo.SetShortName("test_full_info_short_name");
        osAccountInfo.SetType(OsAccountType::NORMAL);
        osAccountInfo.SetCreateTime(TEST_TIME_STAMP);
        osAccountInfo.SetLastLoginTime(TEST_TIME_STAMP);
        dataParcel.WriteParcelable(&osAccountInfo);
        CreateOsAccountOptions options;
        dataParcel.WriteParcelable(&options);
        MessageParcel reply;
        MessageOption option;
        auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
        osAccountManagerService_->OnRemoteRequest(
            static_cast<uint32_t>(IOsAccountIpcCode::COMMAND_CREATE_OS_ACCOUNT_WITH_FULL_INFO),
            dataParcel, reply, option);
        osAccountManagerService_->OnRemoteRequest(
            static_cast<uint32_t>(IOsAccountIpcCode::COMMAND_CREATE_OS_ACCOUNT_WITH_FULL_INFO_IN_OSACCOUNTINFO),
            dataParcel, reply, option);
    }
} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::InitOsAccountWithFullInfo();
    OHOS::UpdateOsAccountWithFullInfo();
    OHOS::SetProfilePhoto();
    OHOS::CleanOsAccount();
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::CreateOsAccountWithFullInfoStubFuzzTest(data, size);
    return 0;
}
