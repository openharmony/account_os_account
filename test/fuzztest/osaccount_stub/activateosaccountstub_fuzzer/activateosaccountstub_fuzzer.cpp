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

#include "activateosaccountstub_fuzzer.h"
#include <string>
#include <thread>
#include <vector>

#include "fuzz_data.h"
#include "ios_account.h"
#include "os_account_manager_service.h"

using namespace std;
using namespace OHOS::AccountSA;

namespace OHOS {
const int ENUM_TYPE_MAX = 5;
const int PRIVATE_NUMBER = 3;
const int END_NUMBER = 4;
const std::u16string IOS_ACCOUNT_DESCRIPTOR = u"ohos.accountfwk.IOsAccount";
bool ActivateOsAccountStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    MessageParcel datas;
    FuzzData fuzzData(data, size);
    datas.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR);

    if (!datas.WriteInt32(fuzzData.GetData<int32_t>())) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
    osAccountManagerService_ ->OnRemoteRequest(
        static_cast<int32_t>(OsAccountInterfaceCode::ACTIVATE_OS_ACCOUNT), datas, reply, option);

    return true;
}

bool ProcCreateOsAccountWithFullInfoStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR)) {
        return false;
    }

    FuzzData fuzzData(data, size);

    OsAccountInfo osAccountInfo;
    osAccountInfo.SetLocalId(fuzzData.GetData<int>());
    osAccountInfo.SetLocalName(fuzzData.GenerateRandomString());
    osAccountInfo.SetShortName(fuzzData.GenerateRandomString());
    int typeNumber = fuzzData.GetData<int>() % ENUM_TYPE_MAX;
    if (typeNumber == PRIVATE_NUMBER) {
        osAccountInfo.SetType(PRIVATE);
    } else if (typeNumber == END_NUMBER) {
        osAccountInfo.SetType(END);
    } else {
        OsAccountType testType = static_cast<OsAccountType>(typeNumber);
        osAccountInfo.SetType(testType);
    }
    osAccountInfo.SetSerialNumber(fuzzData.GetData<int64_t>());

    if (!datas.WriteParcelable(&osAccountInfo)) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
    osAccountManagerService_->OnRemoteRequest(
        static_cast<int32_t>(OsAccountInterfaceCode::CREATE_OS_ACCOUNT_WITH_FULL_INFO), datas, reply, option);

    return true;
}

bool ProcDeactivateAllOsAccountsStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR)) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
    osAccountManagerService_->OnRemoteRequest(
        static_cast<int32_t>(OsAccountInterfaceCode::DEACTIVATE_ALL_OS_ACCOUNTS), datas, reply, option);

    return true;
}

bool ProcGetBackgroundOsAccountLocalIdsStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR)) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
    osAccountManagerService_->OnRemoteRequest(
        static_cast<int32_t>(OsAccountInterfaceCode::GET_BACKGROUND_OS_ACCOUNT_LOCAL_IDS), datas, reply, option);

    return true;
}

bool ProcGetCreatedOsAccountNumFromDatabaseStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR)) {
        return false;
    }

    FuzzData fuzzData(data, size);
    if (!datas.WriteString(fuzzData.GenerateRandomString())) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
    osAccountManagerService_->OnRemoteRequest(
        static_cast<int32_t>(OsAccountInterfaceCode::GET_CREATED_OS_ACCOUNT_NUM_FROM_DATABASE), datas, reply, option);

    return true;
}

bool ProcGetDefaultActivatedOsAccountStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR)) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
    osAccountManagerService_->OnRemoteRequest(
        static_cast<int32_t>(OsAccountInterfaceCode::GET_DEFAULT_ACTIVATED_OS_ACCOUNT), datas, reply, option);

    return true;
}

bool ProcGetForegroundOsAccountsStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR)) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
    osAccountManagerService_->OnRemoteRequest(
        static_cast<int32_t>(OsAccountInterfaceCode::GET_FOREGROUND_OS_ACCOUNTS), datas, reply, option);

    return true;
}

bool ProcGetMaxAllowCreateIdFromDatabaseStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR)) {
        return false;
    }

    FuzzData fuzzData(data, size);
    if (!datas.WriteString(fuzzData.GenerateRandomString())) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
    osAccountManagerService_->OnRemoteRequest(
        static_cast<int32_t>(OsAccountInterfaceCode::GET_MAX_ALLOW_CREATE_ID_FROM_DATABASE), datas, reply, option);

    return true;
}

bool ProcGetOsAccountFromDatabaseStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR)) {
        return false;
    }

    FuzzData fuzzData(data, size);
    if (!datas.WriteString(fuzzData.GenerateRandomString())) {
        return false;
    }

    if (!datas.WriteInt32(fuzzData.GetData<int32_t>())) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
    osAccountManagerService_->OnRemoteRequest(
        static_cast<int32_t>(OsAccountInterfaceCode::GET_OS_ACCOUNT_FROM_DATABASE), datas, reply, option);

    return true;
}

bool ProcGetOsAccountListFromDatabaseStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR)) {
        return false;
    }

    FuzzData fuzzData(data, size);
    if (!datas.WriteString(fuzzData.GenerateRandomString())) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
    osAccountManagerService_->OnRemoteRequest(
        static_cast<int32_t>(OsAccountInterfaceCode::GET_OS_ACCOUNT_LIST_FROM_DATABASE), datas, reply, option);

    return true;
}

bool ProcGetOsAccountShortNameStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR)) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
    osAccountManagerService_->OnRemoteRequest(
        static_cast<int32_t>(OsAccountInterfaceCode::GET_OS_ACCOUNT_SHORT_NAME), datas, reply, option);

    return true;
}

bool ProcGetOsAccountTypeFromProcessStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR)) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
    osAccountManagerService_->OnRemoteRequest(
        static_cast<int32_t>(OsAccountInterfaceCode::GET_OS_ACCOUNT_TYPE_FROM_PROCESS), datas, reply, option);

    return true;
}

bool ProcGetSerialNumberFromDatabaseStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR)) {
        return false;
    }

    FuzzData fuzzData(data, size);
    if (!datas.WriteString(fuzzData.GenerateRandomString())) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
    osAccountManagerService_->OnRemoteRequest(
        static_cast<int32_t>(OsAccountInterfaceCode::GET_SERIAL_NUM_FROM_DATABASE), datas, reply, option);

    return true;
}

bool ProcIsCurrentOsAccountVerifiedStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR)) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
    osAccountManagerService_->OnRemoteRequest(
        static_cast<int32_t>(OsAccountInterfaceCode::IS_CURRENT_OS_ACCOUNT_VERIFIED), datas, reply, option);

    return true;
}

bool ProcIsMultiOsAccountEnableStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR)) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
    osAccountManagerService_->OnRemoteRequest(
        static_cast<int32_t>(OsAccountInterfaceCode::IS_MULTI_OS_ACCOUNT_ENABLE), datas, reply, option);

    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::ActivateOsAccountStubFuzzTest(data, size);
    OHOS::ProcGetCreatedOsAccountNumFromDatabaseStubFuzzTest(data, size);
    OHOS::ProcDeactivateAllOsAccountsStubFuzzTest(data, size);
    OHOS::ProcCreateOsAccountWithFullInfoStubFuzzTest(data, size);
    OHOS::ProcGetBackgroundOsAccountLocalIdsStubFuzzTest(data, size);
    OHOS::ProcGetDefaultActivatedOsAccountStubFuzzTest(data, size);
    OHOS::ProcGetForegroundOsAccountsStubFuzzTest(data, size);
    OHOS::ProcGetMaxAllowCreateIdFromDatabaseStubFuzzTest(data, size);
    OHOS::ProcGetOsAccountFromDatabaseStubFuzzTest(data, size);
    OHOS::ProcGetOsAccountListFromDatabaseStubFuzzTest(data, size);
    OHOS::ProcGetOsAccountShortNameStubFuzzTest(data, size);
    OHOS::ProcGetOsAccountTypeFromProcessStubFuzzTest(data, size);
    OHOS::ProcGetSerialNumberFromDatabaseStubFuzzTest(data, size);
    OHOS::ProcIsCurrentOsAccountVerifiedStubFuzzTest(data, size);
    OHOS::ProcIsMultiOsAccountEnableStubFuzzTest(data, size);
    return 0;
}
