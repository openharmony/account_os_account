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

#ifndef OS_ACCOUNT_TEST_SYSTEMTEST_COMMON_RESOURCE_FUZZTEST_INCLUDE_GET_PARAM_H
#define OS_ACCOUNT_TEST_SYSTEMTEST_COMMON_RESOURCE_FUZZTEST_INCLUDE_GET_PARAM_H

#include <memory>
#include <string>
#include <vector>
#include "app_account_info.h"
#include "app_account_manager.h"
#include "app_account_subscribe_info.h"
#include "app_account_subscriber.h"
#include "os_account_manager.h"

namespace OHOS {
namespace AccountSA {
bool GetBoolParam();
uint8_t GetU8Param();
unsigned int GetUIntParam();
uint16_t GetU16Param();
uint32_t GetU32Param();
uint64_t GetU64Param();
int8_t GetS8Param();
int16_t GetS16Param();
int32_t GetS32Param();
int64_t GetS64Param();
char32_t GetChar32Param();

short GetShortParam();
long GetLongParam();
int GetIntParam();
double GetDoubleParam();
float GetFloatParam();
char GetCharParam();
char *GetCharArryParam();
std::string GetStringParam();
std::vector<bool> GetBoolVectorParam();
std::vector<short> GetShortVectorParam();
std::vector<long> GetLongVectorParam();
std::vector<int> GetIntVectorParam();
std::vector<float> GetFloatVectorParam();
std::vector<double> GetDoubleVectorParam();
std::vector<char> GetCharVectorParam();
std::vector<char32_t> GetChar32VectorParam();
std::vector<std::string> GetStringVectorParam();
template<class T>
std::vector<T> GetUnsignVectorParam();
std::vector<int8_t> GetS8VectorParam();
std::vector<int16_t> GetS16VectorParam();
std::vector<int32_t> GetS32VectorParam();
std::vector<int64_t> GetS64VectorParam();
OsAccountType GetParamOsAccountType();
OsAccountInfo GetParamOsAccountInfo();
DomainAccountInfo GetParamDomainAccountInfo();

AppAccountInfo GetParamAppAccountInfo();
std::vector<AppAccountInfo> GetVectorParamAppAccountInfo();
std::shared_ptr<AppAccountSubscriber> GetAppAccountSubscriber();

class TestAppAccountSubscriber : public AppAccountSubscriber {
public:
    TestAppAccountSubscriber() {}
    ~TestAppAccountSubscriber() {}
    virtual void OnAccountsChanged(const std::vector<AppAccountInfo> &accounts)
    {
        printf("Fuzz Test OnAccountsChanged\n");
    }
};

class TestOsAccountSubscriber : public OsAccountSubscriber {
public:
    TestOsAccountSubscriber() {};
    ~TestOsAccountSubscriber() {};
    virtual void OnAccountsChanged(const int &id)
    {
        printf("Fuzz Test OnAccountsChanged\n");
    }
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_TEST_SYSTEMTEST_COMMON_RESOURCE_FUZZTEST_INCLUDE_GET_PARAM_H