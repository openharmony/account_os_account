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

#include "createosaccountfordomain_fuzzer.h"

#include <string>
#include <vector>
#include "os_account_manager.h"
#include "account_log_wrapper.h"
#include "fuzz_data.h"
#include "os_account.h"
#include "os_account_constants.h"
#include "os_account_manager_service.h"
#include "os_account_proxy.h"
#include "securec.h"

using namespace std;
using namespace OHOS::AccountSA;

namespace OHOS {
constexpr uint32_t MAX_ACCOUNT_TYPE_COUNT = 5;

OsAccountType GetAccountType(FuzzData& fuzzData, bool useValid)
{
    if (useValid) {
        return OsAccountType::NORMAL;
    }
    return static_cast<OsAccountType>(fuzzData.GetData<uint32_t>() % MAX_ACCOUNT_TYPE_COUNT);
}

bool CreateOsAccountForDomainFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzData fuzzData(data, size);
    bool useValidParams = fuzzData.GetData<bool>();
    
    std::string accountName = useValidParams ? "domain.user" : fuzzData.GenerateString();
    std::string domain = useValidParams ? "example.com" : fuzzData.GenerateString();
    DomainAccountInfo domainInfo(accountName, domain);
    OsAccountType testType = GetAccountType(fuzzData, useValidParams);
    OsAccountInfo osAccountInfo;
    
    int32_t result = OsAccountManager::CreateOsAccountForDomain(testType, domainInfo, nullptr);
    if (result == ERR_OK) {
        ACCOUNT_LOGI("CreateOsAccountForDomainFuzzTest RemoveOsAccount");
        OsAccountManager::RemoveOsAccount(osAccountInfo.GetLocalId());
    }

    auto servicePtr = new (std::nothrow) OsAccountManagerService();
    std::shared_ptr<OsAccountProxy> osAccountProxy = std::make_shared<OsAccountProxy>(servicePtr->AsObject());
    result = osAccountProxy->CreateOsAccountForDomain(testType, domainInfo, nullptr);
    if (result == ERR_OK) {
        ACCOUNT_LOGI("CreateOsAccountForDomainFuzzTest RemoveOsAccount");
        OsAccountManager::RemoveOsAccount(osAccountInfo.GetLocalId());
    }

    return result == ERR_OK;
}

void CheckOsAccountStatus()
{
    OsAccountInfo osAccountInfoOne;
    OsAccountType testType = OsAccountType::NORMAL;
    std::string accountName = "fordomain_test_account";
    OsAccountManager::CreateOsAccount(accountName, testType, osAccountInfoOne);
    int32_t localId = osAccountInfoOne.GetLocalId();
    OsAccountManager::ActivateOsAccount(localId);
    OsAccountManager::DeactivateOsAccount(localId);
    std::vector<std::string> states;
    OsAccount::GetInstance().DumpState(localId, states);
    OsAccountType getOsAccountType;
    OsAccountManager::GetOsAccountType(localId, getOsAccountType);
    std::string osAccountName;
    OsAccountManager::GetOsAccountName(osAccountName);
    std::string osAccountShortName;
    OsAccountManager::GetOsAccountShortName(osAccountShortName);
    std::vector<ForegroundOsAccount> accounts;
    OsAccountManager::GetForegroundOsAccounts(accounts);
    unsigned int osAccountsCount;
    OsAccountManager::GetCreatedOsAccountsCount(osAccountsCount);
    std::vector<std::string> constraints;
    OsAccountManager::GetOsAccountAllConstraints(localId, constraints);
    int32_t defaultActivatedOsAccountId;
    OsAccountManager::GetDefaultActivatedOsAccount(defaultActivatedOsAccountId);
    std::vector<int32_t> localIds;
    OsAccountManager::GetBackgroundOsAccountLocalIds(localIds);
    int osAccountLocalId;
    OsAccountManager::GetOsAccountLocalIdFromProcess(osAccountLocalId);
    OsAccountManager::GetOsAccountSwitchMod();
    OsAccountType osAccountType;
    OsAccountManager::GetOsAccountTypeFromProcess(osAccountType);
    std::vector<int32_t> activeOsAccountIds;
    OsAccountManager::QueryActiveOsAccountIds(activeOsAccountIds);
    OsAccountInfo osAccountInfo;
    OsAccountManager::QueryCurrentOsAccount(osAccountInfo);
    std::vector<OsAccountInfo> osAccountInfos;
    OsAccountManager::QueryAllCreatedOsAccounts(osAccountInfos);
    uint32_t maxNum;
    OsAccountManager::QueryMaxLoggedInOsAccountNumber(maxNum);
    uint32_t maxOsAccountNumber;
    OsAccountManager::QueryMaxOsAccountNumber(maxOsAccountNumber);
    bool isVerified;
    OsAccountManager::IsCurrentOsAccountVerified(isVerified);
    bool isMainOsAccount;
    OsAccountManager::IsMainOsAccount(isMainOsAccount);
    bool isMultiOsAccountEnable;
    OsAccountManager::IsMultiOsAccountEnable(isMultiOsAccountEnable);
    OsAccountManager::DeactivateAllOsAccounts();
}
} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::CheckOsAccountStatus();
    return 0;
}
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::CreateOsAccountForDomainFuzzTest(data, size);
    return 0;
}
