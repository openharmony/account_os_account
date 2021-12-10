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

#include "app_account_manager.h"
#include "fuzzConfigParser.h"
#include "hilog_wrapper.h"
#include <unistd.h>
#include "../include/getparam.h"
#include "../include/fuzzTestManager.h"

#undef private
#undef protected
namespace OHOS {
namespace AccountSA {
std::shared_ptr<fuzzTestManager> fuzzTestManager::instance_ = nullptr;

// AppAccount
void fuzzTestManager::RegisterAppAccountManager()
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
        AppAccountManager::GetOAuthToken(GetStringParam(), token);
    };
    callFunctionMap_["AppAccountManagerSetOAuthToken"] = []() {
        AppAccountManager::SetOAuthToken(GetStringParam(), GetStringParam());
    };
    callFunctionMap_["AppAccountManagerClearOAuthToken"] = []() {
        AppAccountManager::ClearOAuthToken(GetStringParam());
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

fuzzTestManager::fuzzTestManager()
{
    RegisterAppAccountManager();
}

void fuzzTestManager::SetJsonFunction(std::string functionName)
{
    remainderMap_.emplace(functionName, cycle_);
}

void fuzzTestManager::SetCycle(uint16_t cycle)
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

void fuzzTestManager::StartFuzzTest()
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
            it++;
        }
    }

    std::cout << remainderMap_.size() << "--------fuzz test start--------" << callFunctionMap_.size() << std::endl;
    for (; remainderMap_.size() > 0;) {
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
