/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#ifndef ACCOUNT_FUZZTESTMANAGER_H
#define ACCOUNT_FUZZTESTMANAGER_H
#include "fuzz_test_manager.h"
#include <unistd.h>
#include "app_account_manager.h"
#include "fuzz_config_parser.h"
#include "getparam.h"
#include "hilog_wrapper.h"

#undef private
#undef protected
namespace OHOS {
namespace AccountSA {
std::shared_ptr<FuzzTestManager> FuzzTestManager::instance_ = nullptr;

// AppAccount
void FuzzTestManager::RegisterAppAccountManager()
{
    callFunctionMap_["AppAccountManagerAddAccount"] = []() { AppAccountManager::AddAccount(GetStringParam()); };
    callFunctionMap_["AppAccountManagerDeleteAccount"] = []() { AppAccountManager::DeleteAccount(GetStringParam()); };
    callFunctionMap_["AppAccountManagerGetAccountExtraInfo"] = []() {
        std::string extraInfo = GetStringParam();
        AppAccountManager::GetAccountExtraInfo(GetStringParam(), extraInfo);
    };
    callFunctionMap_["AppAccountManagerSetAccountExtraInfo"] = []() {
        AppAccountManager::SetAccountExtraInfo(GetStringParam(), GetStringParam());
    };
    callFunctionMap_["AppAccountManagerEnableAppAccess"] = []() {
        AppAccountManager::EnableAppAccess(GetStringParam(), GetStringParam());
    };
    callFunctionMap_["AppAccountManagerDisableAppAccess"] = []() {
        AppAccountManager::DisableAppAccess(GetStringParam(), GetStringParam());
    };
    callFunctionMap_["AppAccountManagerCheckAppAccountSyncEnable"] = []() {
        bool syncEnable = GetBoolParam();
        AppAccountManager::CheckAppAccountSyncEnable(GetStringParam(), syncEnable);
    };
    callFunctionMap_["AppAccountManagerSetAppAccountSyncEnable"] = []() {
        AppAccountManager::SetAppAccountSyncEnable(GetStringParam(), GetBoolParam());
    };
    callFunctionMap_["AppAccountManagerGetAssociatedData"] = []() {
        std::string value = GetStringParam();
        AppAccountManager::GetAssociatedData(GetStringParam(), GetStringParam(), value);
    };
    callFunctionMap_["AppAccountManagerSetAssociatedData"] = []() {
        AppAccountManager::SetAssociatedData(GetStringParam(), GetStringParam(), GetStringParam());
    };
    callFunctionMap_["AppAccountManagerGetAccountCredential"] = []() {
        std::string credential = GetStringParam();
        AppAccountManager::GetAccountCredential(GetStringParam(), GetStringParam(), credential);
    };
    callFunctionMap_["AppAccountManagerSetAccountCredential"] = []() {
        AppAccountManager::SetAccountCredential(GetStringParam(), GetStringParam(), GetStringParam());
    };
    callFunctionMap_["AppAccountManagerGetOAuthToken"] = []() {
        std::string token = GetStringParam();
        AppAccountManager::GetOAuthToken(GetStringParam(), GetStringParam(), GetStringParam(), token);
    };
    callFunctionMap_["AppAccountManagerSetOAuthToken"] = []() {
        AppAccountManager::SetOAuthToken(GetStringParam(), GetStringParam(), GetStringParam());
    };
    callFunctionMap_["AppAccountManagerGetAllAccounts"] = []() {
        std::vector<AppAccountInfo> param = GetVectorParamAppAccountInfo();
        AppAccountManager::GetAllAccounts(GetStringParam(), param);
    };
    callFunctionMap_["AppAccountManagerGetAllAccessibleAccounts"] = []() {
        std::vector<AppAccountInfo> param = GetVectorParamAppAccountInfo();
        AppAccountManager::GetAllAccessibleAccounts(param);
    };
    callFunctionMap_["AppAccountManagerSubscribeAppAccount"] = []() {
        AppAccountManager::SubscribeAppAccount(GetAppAccountSubscriber());
    };
    callFunctionMap_["AppAccountManagerUnsubscribeAppAccount"] = []() {
        AppAccountManager::UnsubscribeAppAccount(GetAppAccountSubscriber());
    };
}

// OsAccount
void FuzzTestManager::RegisterOsAccountManager()
{
    callFunctionMap_["OsAccountManagerCreateOsAccount"] = []() {
        OsAccountInfo osAccountInfo = GetParamOsAccountInfo();
        OsAccountManager::CreateOsAccount(GetStringParam(), GetParamOsAccountType(), osAccountInfo);
    };

    callFunctionMap_["OsAccountManagerCreateOsAccountForDomain"] = []() {
        OsAccountInfo osAccountInfo = GetParamOsAccountInfo();
        DomainAccountInfo domainAccountInfo = GetParamDomainAccountInfo();
        OsAccountManager::CreateOsAccountForDomain(GetParamOsAccountType(), domainAccountInfo, osAccountInfo);
    };

    callFunctionMap_["OsAccountManagerRemoveOsAccount"] = []() { OsAccountManager::RemoveOsAccount(GetIntParam()); };

    callFunctionMap_["OsAccountManagerIsOsAccountExists"] = []() {
        bool isOsAccountExists = GetBoolParam();
        OsAccountManager::IsOsAccountExists(GetIntParam(), isOsAccountExists);
    };

    callFunctionMap_["OsAccountManagerIsOsAccountActived"] = []() {
        bool isOsAccountActived = GetBoolParam();
        OsAccountManager::IsOsAccountActived(GetIntParam(), isOsAccountActived);
    };

    callFunctionMap_["OsAccountManagerIsOsAccountConstraintEnable"] = []() {
        bool isConstraintEnable = GetBoolParam();
        std::string constraint = GetStringParam();
        OsAccountManager::IsOsAccountConstraintEnable(GetIntParam(), constraint, isConstraintEnable);
    };

    callFunctionMap_["OsAccountManagerIsOsAccountVerified"] = []() {
        bool isVerified = GetBoolParam();
        OsAccountManager::IsOsAccountVerified(GetIntParam(), isVerified);
    };

    callFunctionMap_["OsAccountManagerGetCreatedOsAccountsCount"] = []() {
        unsigned int osAccountsCount = GetUIntParam();
        OsAccountManager::GetCreatedOsAccountsCount(osAccountsCount);
    };

    callFunctionMap_["OsAccountManagerGetOsAccountLocalIdFromProcess"] = []() {
        int id = GetIntParam();
        OsAccountManager::GetOsAccountLocalIdFromProcess(id);
    };

    callFunctionMap_["OsAccountManagerGetOsAccountLocalIdFromUid"] = []() {
        int id = GetIntParam();
        OsAccountManager::GetOsAccountLocalIdFromUid(GetIntParam(), id);
    };

    callFunctionMap_["OsAccountManagerGetOsAccountLocalIdFromDomain"] = []() {
        int id = GetIntParam();
        DomainAccountInfo domainAccountInfo = GetParamDomainAccountInfo();
        OsAccountManager::GetOsAccountLocalIdFromDomain(domainAccountInfo, id);
    };

    callFunctionMap_["OsAccountManagerQueryMaxOsAccountNumber"] = []() {
        int maxOsAccountNumber = GetIntParam();
        OsAccountManager::QueryMaxOsAccountNumber(maxOsAccountNumber);
    };

    callFunctionMap_["OsAccountManagerGetOsAccountAllConstraints"] = []() {
        std::vector<std::string> constraints = GetStringVectorParam();
        OsAccountManager::GetOsAccountAllConstraints(GetIntParam(), constraints);
    };

    callFunctionMap_["OsAccountManagerQueryAllCreatedOsAccounts"] = []() {
        std::vector<OsAccountInfo> osAccountInfos;
        OsAccountManager::QueryAllCreatedOsAccounts(osAccountInfos);
    };

    callFunctionMap_["OsAccountManagerQueryActiveOsAccountIds"] = []() {
        std::vector<int> osAccountIds;
        OsAccountManager::QueryActiveOsAccountIds(osAccountIds);
    };

    callFunctionMap_["OsAccountManagerQueryCurrentOsAccount"] = []() {
        OsAccountInfo osAccountInfo = GetParamOsAccountInfo();
        OsAccountManager::QueryCurrentOsAccount(osAccountInfo);
    };

    callFunctionMap_["OsAccountManagerQueryOsAccountById"] = []() {
        OsAccountInfo osAccountInfo = GetParamOsAccountInfo();
        OsAccountManager::QueryOsAccountById(GetIntParam(), osAccountInfo);
    };

    callFunctionMap_["OsAccountManagerGetOsAccountTypeFromProcess"] = []() {
        OsAccountType type = GetParamOsAccountType();
        OsAccountManager::GetOsAccountTypeFromProcess(type);
    };

    callFunctionMap_["OsAccountManagerGetOsAccountProfilePhoto"] = []() {
        std::string photo = GetStringParam();
        OsAccountManager::GetOsAccountProfilePhoto(GetIntParam(), photo);
    };

    callFunctionMap_["OsAccountManagerIsMultiOsAccountEnable"] = []() {
        bool isMultiOsAccountEnable = GetBoolParam();
        OsAccountManager::IsMultiOsAccountEnable(isMultiOsAccountEnable);
    };

    callFunctionMap_["OsAccountManagerSetOsAccountName"] = []() {
        std::string localName = GetStringParam();
        OsAccountManager::SetOsAccountName(GetIntParam(), localName);
    };

    callFunctionMap_["OsAccountManagerSetOsAccountConstraints"] = []() {
        std::vector<std::string> constraints = GetStringVectorParam();
        OsAccountManager::SetOsAccountConstraints(GetIntParam(), constraints, GetBoolParam());
    };

    callFunctionMap_["OsAccountManagerSetOsAccountProfilePhoto"] = []() {
        std::string photo = GetStringParam();
        OsAccountManager::SetOsAccountProfilePhoto(GetIntParam(), photo);
    };

    callFunctionMap_["OsAccountManagerGetDistributedVirtualDeviceId"] = []() {
        std::string deviceId = GetStringParam();
        OsAccountManager::GetDistributedVirtualDeviceId(deviceId);
    };

    callFunctionMap_["OsAccountManagerActivateOsAccount"] = []() {
        int id = GetIntParam();
        OsAccountManager::ActivateOsAccount(id);
    };

    callFunctionMap_["OsAccountManagerStartOsAccount"] = []() {
        int id = GetIntParam();
        OsAccountManager::StartOsAccount(id);
    };

    callFunctionMap_["OsAccountManagerStopOsAccount"] = []() {
        int id = GetIntParam();
        OsAccountManager::StopOsAccount(id);
    };

    callFunctionMap_["OsAccountManagerGetOsAccountLocalIdBySerialNumber"] = []() {
        int id = GetIntParam();
        int64_t serialNumber = GetS64Param();
        OsAccountManager::GetOsAccountLocalIdBySerialNumber(serialNumber, id);
    };

    callFunctionMap_["OsAccountManagerGetSerialNumberByOsAccountLocalId"] = []() {
        int id = GetIntParam();
        int64_t serialNumber = GetS64Param();
        OsAccountManager::GetSerialNumberByOsAccountLocalId(id, serialNumber);
    };

    callFunctionMap_["OsAccountManagerSubscribeOsAccount"] = []() {
        std::shared_ptr<TestOsAccountSubscriber> subscriber;
        OsAccountManager::SubscribeOsAccount(subscriber);
    };

    callFunctionMap_["OsAccountManagerUnsubscribeOsAccount"] = []() {
        std::shared_ptr<TestOsAccountSubscriber> subscriber;
        OsAccountManager::UnsubscribeOsAccount(subscriber);
    };

    callFunctionMap_["OsAccountManagerGetOsAccountSwitchMod"] = []() { OsAccountManager::GetOsAccountSwitchMod(); };

    callFunctionMap_["OsAccountManagerIsCurrentOsAccountVerified"] = []() {
        bool isVerified = GetBoolParam();
        OsAccountManager::IsCurrentOsAccountVerified(isVerified);
    };

    callFunctionMap_["OsAccountManagerIsOsAccountCompleted"] = []() {
        bool isOsAccountCompleted = GetBoolParam();
        OsAccountManager::IsOsAccountCompleted(GetIntParam(), isOsAccountCompleted);
    };

    callFunctionMap_["OsAccountManagerSetCurrentOsAccountIsVerified"] = []() {
        bool isVerified = GetBoolParam();
        OsAccountManager::SetCurrentOsAccountIsVerified(isVerified);
    };

    callFunctionMap_["OsAccountManagerSetOsAccountIsVerified"] = []() {
        OsAccountManager::SetOsAccountIsVerified(GetIntParam(), GetBoolParam());
    };

    callFunctionMap_["OsAccountManagerGetCreatedOsAccountNumFromDatabase"] = []() {
        std::string storeID = GetStringParam();
        int createdOsAccountNum = GetIntParam();
        OsAccountManager::GetCreatedOsAccountNumFromDatabase(storeID, createdOsAccountNum);
    };

    callFunctionMap_["OsAccountManagerGetSerialNumberFromDatabase"] = []() {
        std::string storeID = GetStringParam();
        int64_t serialNumber = GetS64Param();
        OsAccountManager::GetSerialNumberFromDatabase(storeID, serialNumber);
    };

    callFunctionMap_["OsAccountManagerGetMaxAllowCreateIdFromDatabase"] = []() {
        std::string storeID = GetStringParam();
        int id = GetIntParam();
        OsAccountManager::GetMaxAllowCreateIdFromDatabase(storeID, id);
    };

    callFunctionMap_["OsAccountManagerGetOsAccountFromDatabase"] = []() {
        std::string storeID = GetStringParam();
        int id = GetIntParam();
        OsAccountInfo osAccountInfo = GetParamOsAccountInfo();
        OsAccountManager::GetOsAccountFromDatabase(storeID, id, osAccountInfo);
    };

    callFunctionMap_["OsAccountManagerGetOsAccountListFromDatabase"] = []() {
        std::string storeID = GetStringParam();
        std::vector<OsAccountInfo> osAccountList;
        OsAccountManager::GetOsAccountListFromDatabase(storeID, osAccountList);
    };
}

FuzzTestManager::FuzzTestManager()
{
    RegisterAppAccountManager();
    RegisterOsAccountManager();
}

void FuzzTestManager::SetJsonFunction(std::string functionName)
{
    remainderMap_.emplace(functionName, cycle_);
}

void FuzzTestManager::SetCycle(uint16_t cycle)
{
    cycle_ = cycle;
    for_each(remainderMap_.begin(), remainderMap_.end(), [cycle](std::unordered_map<std::string, int>::reference temp) {
        temp.second = cycle;
    });
}

int GetRandomInt(int minNum, int maxNum)
{
    return GetU16Param() % (maxNum - minNum + 1) + minNum;
}

void action(int a)
{
    std::cout << "Interrupt signal (" << a << ") received.\n";
}

void FuzzTestManager::StartFuzzTest()
{
    std::cout << __func__ << std::endl;
    OHOS::FuzzConfigParser jsonParser;
    OHOS::FuzzTestData tempData;

    std::cout << "parseFromFile start" << std::endl;
    jsonParser.ParseFromFile4FuzzTest(FUZZ_TEST_CONFIG_FILE_PATH, tempData);
    std::cout << "flag :" << tempData.mainLoopFlag << std::endl;
    for_each(tempData.methodVec.begin(), tempData.methodVec.end(), [this](std::vector<std::string>::reference s) {
        SetJsonFunction(s);
    });
    SetCycle(tempData.mainLoopFlag);

    std::vector<std::string> index;
    std::unordered_map<std::string, int>::iterator it = remainderMap_.begin();
    while (it != remainderMap_.end()) {
        if (it->second <= 0) {
            it = remainderMap_.erase(it);
        } else {
            index.push_back(it->first);
            ++it;
        }
    }

    std::cout << remainderMap_.size() << "--------fuzz test start--------" << callFunctionMap_.size() << std::endl;
    while (remainderMap_.size() > 0) {
        std::string functionName;
        int offset = GetRandomInt(0, index.size() - 1);
        functionName = index[offset];
        if (callFunctionMap_.find(functionName) != callFunctionMap_.end()) {
            std::cout << "call function : " << functionName << std::endl;
            callFunctionMap_[functionName]();
            std::cout << "function end  :" << functionName << std::endl;
        } else {
            std::cout << "can't find function : " << functionName << std::endl;
        }
        remainderMap_[functionName]--;
        if (remainderMap_[functionName] <= 0) {
            remainderMap_.erase(functionName);
            index.erase(index.begin() + offset);
        };
    }
    std::cout << remainderMap_.size() << "--------fuzz test end--------" << std::endl;
}
}  // namespace AccountSA
}  // namespace OHOS
#endif