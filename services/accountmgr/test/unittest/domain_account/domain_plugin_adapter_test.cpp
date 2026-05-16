/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <cerrno>
#include <gtest/gtest.h>
#include <map>
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "domain_plugin_adapter.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string TEST_DOMAIN = "testDomain";
const std::string TEST_ACCOUNT_NAME = "testAccountName";
const std::string TEST_ACCOUNT_ID = "testAccountId";
const std::string TEST_SERVER_CONFIG_ID = "testServerConfigId";
const std::string TEST_TRUE_NAME_1 = "testTrueName1";
const std::string TEST_TRUE_NAME_2 = "testTrueName2";
} // namespace

class DomainPluginAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DomainPluginAdapterTest::SetUpTestCase(void)
{}

void DomainPluginAdapterTest::TearDownTestCase(void)
{}

void DomainPluginAdapterTest::SetUp(void)
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void DomainPluginAdapterTest::TearDown(void)
{}

/**
 * @tc.name: DomainPluginAdapterTest_GetMethodNameByEnum_001
 * @tc.desc: GetMethodNameByEnum with invalid enum value.
 * @tc.type: FUNC
 * @tc.cover: lines 59-60
 * @tc.require:
 */
HWTEST_F(DomainPluginAdapterTest, DomainPluginAdapterTest_GetMethodNameByEnum_001, TestSize.Level3)
{
    std::string result = GetMethodNameByEnum(static_cast<PluginMethodEnum>(999));
    EXPECT_EQ(result, "");
}

/**
 * @tc.name: DomainPluginAdapterTest_LoadPlugin_001
 * @tc.desc: LoadPlugin with nullptr libHandle.
 * @tc.type: FUNC
 * @tc.cover: lines 73-74
 * @tc.require:
 */
HWTEST_F(DomainPluginAdapterTest, DomainPluginAdapterTest_LoadPlugin_001, TestSize.Level3)
{
    std::map<PluginMethodEnum, void*> methodMap;
    bool result = DomainPluginAdapter::GetInstance().LoadPlugin(
        nullptr, &methodMap, "/test/", "test.z.so");
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: DomainPluginAdapterTest_LoadPlugin_002
 * @tc.desc: LoadPlugin with nullptr methodMap.
 * @tc.type: FUNC
 * @tc.cover: lines 73-74
 * @tc.require:
 */
HWTEST_F(DomainPluginAdapterTest, DomainPluginAdapterTest_LoadPlugin_002, TestSize.Level3)
{
    void* libHandle = nullptr;
    bool result = DomainPluginAdapter::GetInstance().LoadPlugin(
        &libHandle, nullptr, "/test/", "test.z.so");
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: DomainPluginAdapterTest_LoadPlugin_003
 * @tc.desc: LoadPlugin with invalid path, dlerror returns nullptr.
 * @tc.type: FUNC
 * @tc.cover: line 81
 * @tc.require:
 */
HWTEST_F(DomainPluginAdapterTest, DomainPluginAdapterTest_LoadPlugin_003, TestSize.Level3)
{
    errno = 0;
    void* libHandle = nullptr;
    std::map<PluginMethodEnum, void*> methodMap;
    bool result = DomainPluginAdapter::GetInstance().LoadPlugin(
        &libHandle, &methodMap, "/invalidPath/", "invalid.z.so");
    EXPECT_EQ(result, false);
    EXPECT_EQ(libHandle, nullptr);
}

/**
 * @tc.name: DomainPluginAdapterTest_LoadPlugin_004
 * @tc.desc: LoadPlugin with method that dlsym fails.
 * @tc.type: FUNC
 * @tc.cover: lines 103-111
 * @tc.require:
 */
HWTEST_F(DomainPluginAdapterTest, DomainPluginAdapterTest_LoadPlugin_004, TestSize.Level3)
{
    void* libHandle1 = reinterpret_cast<void*>(1);
    DomainPluginAdapter::GetInstance().ClosePlugin(&libHandle1, nullptr);
    void* libHandle = nullptr;
    std::map<PluginMethodEnum, void*> methodMap;
    DomainPluginAdapter::GetInstance().ClosePlugin(nullptr, &methodMap);
    DomainPluginAdapter::GetInstance().ClosePlugin(&libHandle, &methodMap);
    bool result = DomainPluginAdapter::GetInstance().LoadPlugin(
        &libHandle, &methodMap, "/rightPath/", "missingMethod.z.so");
    EXPECT_EQ(result, false);
    EXPECT_EQ(libHandle, nullptr);
    EXPECT_EQ(methodMap.size(), 0);
}

/**
 * @tc.name: DomainPluginAdapterTest_GetAndCleanPluginAuthStatusInfo_003
 * @tc.desc: GetAndCleanPluginAuthStatusInfo normal case.
 * @tc.type: FUNC
 * @tc.cover: lines 348-352
 * @tc.require:
 */
HWTEST_F(DomainPluginAdapterTest, DomainPluginAdapterTest_GetAndCleanPluginAuthStatusInfo_003, TestSize.Level3)
{
    AuthStatusInfo result;
    DomainPluginAdapter::GetAndCleanPluginAuthStatusInfo(nullptr, result);
    PluginAuthStatusInfo* statusInfo1 = nullptr;
    DomainPluginAdapter::GetAndCleanPluginAuthStatusInfo(&statusInfo1, result);
    PluginAuthStatusInfo* statusInfo = (PluginAuthStatusInfo*)malloc(sizeof(PluginAuthStatusInfo));
    ASSERT_NE(statusInfo, nullptr);
    statusInfo->freezingTime = 100;
    statusInfo->remainTimes = 5;
    statusInfo->nextPhaseFreezingTime = 200;

    DomainPluginAdapter::GetAndCleanPluginAuthStatusInfo(&statusInfo, result);
    EXPECT_EQ(result.freezingTime, 100);
    EXPECT_EQ(result.remainingTimes, 5);
    EXPECT_EQ(result.nextPhaseFreezingTime, 200);
    EXPECT_EQ(statusInfo, nullptr);
}

/**
 * @tc.name: DomainPluginAdapterTest_GetAndCleanPluginDomainAccountPolicy_003
 * @tc.desc: GetAndCleanPluginDomainAccountPolicy normal case.
 * @tc.type: FUNC
 * @tc.cover: lines 362-364
 * @tc.require:
 */
HWTEST_F(DomainPluginAdapterTest, DomainPluginAdapterTest_GetAndCleanPluginDomainAccountPolicy_003, TestSize.Level3)
{
    std::string policy;
    DomainPluginAdapter::GetAndCleanPluginDomainAccountPolicy(nullptr, policy);
    PluginDomainAccountPolicy* accountPolicy1 = nullptr;
    DomainPluginAdapter::GetAndCleanPluginDomainAccountPolicy(&accountPolicy1, policy);

    PluginDomainAccountPolicy* accountPolicy = (PluginDomainAccountPolicy*)malloc(sizeof(PluginDomainAccountPolicy));
    ASSERT_NE(accountPolicy, nullptr);
    accountPolicy->parameters.data = strdup("testPolicy");
    accountPolicy->parameters.length = strlen("testPolicy");

    DomainPluginAdapter::GetAndCleanPluginDomainAccountPolicy(&accountPolicy, policy);
    EXPECT_EQ(policy, "testPolicy");
    EXPECT_EQ(accountPolicy, nullptr);
}

/**
 * @tc.name: DomainPluginAdapterTest_SetPluginDomainAccountInfo_001
 * @tc.desc: SetPluginDomainAccountInfo with GetOsAccountLocalIdFromDomain failed.
 * @tc.type: FUNC
 * @tc.cover: lines 285-287
 * @tc.require:
 */
HWTEST_F(DomainPluginAdapterTest, DomainPluginAdapterTest_SetPluginDomainAccountInfo_001, TestSize.Level3)
{
    DomainAccountInfo info;
    info.domain_ = TEST_DOMAIN;
    info.accountName_ = TEST_ACCOUNT_NAME;
    info.accountId_ = TEST_ACCOUNT_ID;
    PluginDomainAccountInfo pluginInfo;
    DomainPluginAdapter::SetPluginDomainAccountInfo(info, pluginInfo);
    EXPECT_EQ(pluginInfo.serverConfigId.data, nullptr);
}

/**
 * @tc.name: DomainPluginAdapterTest_SetPluginDomainAccountInfo_002
 * @tc.desc: SetPluginDomainAccountInfo with GetRealOsAccountInfoById failed.
 * @tc.type: FUNC
 * @tc.cover: lines 292-294
 * @tc.require:
 */
HWTEST_F(DomainPluginAdapterTest, DomainPluginAdapterTest_SetPluginDomainAccountInfo_002, TestSize.Level3)
{
    DomainAccountInfo info;
    info.domain_ = TEST_DOMAIN;
    info.accountName_ = TEST_TRUE_NAME_1;
    info.accountId_ = TEST_ACCOUNT_ID;
    PluginDomainAccountInfo pluginInfo;
    DomainPluginAdapter::SetPluginDomainAccountInfo(info, pluginInfo);
    EXPECT_EQ(pluginInfo.serverConfigId.data, nullptr);
}

/**
 * @tc.name: DomainPluginAdapterTest_SetPluginDomainAccountInfo_003
 * @tc.desc: SetPluginDomainAccountInfo with serverConfigId provided.
 * @tc.type: FUNC
 * @tc.cover: lines 270-272
 * @tc.require:
 */
HWTEST_F(DomainPluginAdapterTest, DomainPluginAdapterTest_SetPluginDomainAccountInfo_003, TestSize.Level3)
{
    DomainAccountInfo info;
    info.domain_ = TEST_DOMAIN;
    info.accountName_ = TEST_TRUE_NAME_2;
    info.accountId_ = TEST_ACCOUNT_ID;
    info.serverConfigId_ = TEST_SERVER_CONFIG_ID;
    PluginDomainAccountInfo pluginInfo;
    DomainPluginAdapter::SetPluginDomainAccountInfo(info, pluginInfo);
    EXPECT_NE(pluginInfo.serverConfigId.data, nullptr);
    EXPECT_EQ(string(pluginInfo.serverConfigId.data), TEST_SERVER_CONFIG_ID);
    DomainPluginAdapter::CleanPluginString(&(pluginInfo.serverConfigId.data), pluginInfo.serverConfigId.length);
}

/**
 * @tc.name: DomainPluginAdapterTest_CleanPluginString_003
 * @tc.desc: CleanPluginString normal case.
 * @tc.type: FUNC
 * @tc.cover: lines 159-161
 * @tc.require:
 */
HWTEST_F(DomainPluginAdapterTest, DomainPluginAdapterTest_CleanPluginString_003, TestSize.Level3)
{
    DomainPluginAdapter::CleanPluginString(nullptr, 0);
    char* data1 = nullptr;
    DomainPluginAdapter::CleanPluginString(&data1, 0);
    char* data = strdup("testData");
    ASSERT_NE(data, nullptr);
    size_t length = strlen("testData");
    DomainPluginAdapter::CleanPluginString(&data, length);
    EXPECT_EQ(data, nullptr);
}

/**
 * @tc.name: DomainPluginAdapterTest_GetAndCleanPluginBusinessError_001
 * @tc.desc: GetAndCleanPluginBusinessError with error nullptr.
 * @tc.type: FUNC
 * @tc.cover: line 198
 * @tc.require:
 */
HWTEST_F(DomainPluginAdapterTest, DomainPluginAdapterTest_GetAndCleanPluginBusinessError_001, TestSize.Level3)
{
    DomainAccountInfo info;
    ErrCode result = DomainPluginAdapter::GetAndCleanPluginBusinessError(
        nullptr, PluginMethodEnum::AUTH, 0, info);
    EXPECT_EQ(result, ERR_JS_SYSTEM_SERVICE_EXCEPTION);
}

/**
 * @tc.name: DomainPluginAdapterTest_GetAndCleanPluginBusinessError_002
 * @tc.desc: GetAndCleanPluginBusinessError with *error nullptr.
 * @tc.type: FUNC
 * @tc.cover: line 198
 * @tc.require:
 */
HWTEST_F(DomainPluginAdapterTest, DomainPluginAdapterTest_GetAndCleanPluginBusinessError_002, TestSize.Level3)
{
    PluginBusinessError* error = nullptr;
    DomainAccountInfo info;
    ErrCode result = DomainPluginAdapter::GetAndCleanPluginBusinessError(
        &error, PluginMethodEnum::AUTH, 0, info);
    EXPECT_EQ(result, ERR_JS_SYSTEM_SERVICE_EXCEPTION);
}

/**
 * @tc.name: DomainPluginAdapterTest_GetAndCleanPluginBusinessError_003
 * @tc.desc: GetAndCleanPluginBusinessError normal case with msg.
 * @tc.type: FUNC
 * @tc.cover: lines 206-225
 * @tc.require:
 */
HWTEST_F(DomainPluginAdapterTest, DomainPluginAdapterTest_GetAndCleanPluginBusinessError_003, TestSize.Level3)
{
    PluginBusinessError* error = (PluginBusinessError*)malloc(sizeof(PluginBusinessError));
    ASSERT_NE(error, nullptr);
    error->code = 0;
    error->msg.data = strdup("testMsg");
    error->msg.length = strlen("testMsg");
    DomainAccountInfo info;
    ErrCode result = DomainPluginAdapter::GetAndCleanPluginBusinessError(
        &error, PluginMethodEnum::AUTH, 0, info);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(error, nullptr);
}

/**
 * @tc.name: DomainPluginAdapterTest_GetAndCleanPluginServerConfigInfo_003
 * @tc.desc: GetAndCleanPluginServerConfigInfo normal case.
 * @tc.type: FUNC
 * @tc.cover: lines 251-255
 * @tc.require:
 */
HWTEST_F(DomainPluginAdapterTest, DomainPluginAdapterTest_GetAndCleanPluginServerConfigInfo_003, TestSize.Level3)
{
    std::string id, domain, parameters;
    DomainPluginAdapter::GetAndCleanPluginServerConfigInfo(nullptr, id, domain, parameters);
    PluginServerConfigInfo* configInfo1 = nullptr;
    DomainPluginAdapter::GetAndCleanPluginServerConfigInfo(&configInfo1, id, domain, parameters);
    PluginServerConfigInfo* configInfo = (PluginServerConfigInfo*)malloc(sizeof(PluginServerConfigInfo));
    ASSERT_NE(configInfo, nullptr);
    configInfo->id.data = strdup("testId");
    configInfo->id.length = strlen("testId");
    configInfo->domain.data = strdup("testDomain");
    configInfo->domain.length = strlen("testDomain");
    configInfo->parameters.data = strdup("testParams");
    configInfo->parameters.length = strlen("testParams");
    DomainPluginAdapter::GetAndCleanPluginServerConfigInfo(&configInfo, id, domain, parameters);
    EXPECT_EQ(id, "testId");
    EXPECT_EQ(domain, "testDomain");
    EXPECT_EQ(parameters, "testParams");
    EXPECT_EQ(configInfo, nullptr);
}

/**
 * @tc.name: DomainPluginAdapterTest_GetAndCleanPluginDomainAccountInfo_003
 * @tc.desc: GetAndCleanPluginDomainAccountInfo normal case.
 * @tc.type: FUNC
 * @tc.cover: lines 301-308
 * @tc.require:
 */
HWTEST_F(DomainPluginAdapterTest, DomainPluginAdapterTest_GetAndCleanPluginDomainAccountInfo_003, TestSize.Level3)
{
    DomainAccountInfo info;
    DomainPluginAdapter::GetAndCleanPluginDomainAccountInfo(info, nullptr);
    PluginDomainAccountInfo* domainAccountInfo1 = nullptr;
    DomainPluginAdapter::GetAndCleanPluginDomainAccountInfo(info, &domainAccountInfo1);
    PluginDomainAccountInfo* domainAccountInfo = (PluginDomainAccountInfo*)malloc(sizeof(PluginDomainAccountInfo));
    ASSERT_NE(domainAccountInfo, nullptr);
    domainAccountInfo->serverConfigId.data = strdup("testConfigId");
    domainAccountInfo->serverConfigId.length = strlen("testConfigId");
    domainAccountInfo->domain.data = strdup("testDomain");
    domainAccountInfo->domain.length = strlen("testDomain");
    domainAccountInfo->accountName.data = strdup("testName");
    domainAccountInfo->accountName.length = strlen("testName");
    domainAccountInfo->accountId.data = strdup("testAccountId");
    domainAccountInfo->accountId.length = strlen("testAccountId");
    domainAccountInfo->extraAttributes.data = strdup("testExtra");
    domainAccountInfo->extraAttributes.length = strlen("testExtra");
    domainAccountInfo->isAuthenticated = 1;
    DomainPluginAdapter::GetAndCleanPluginDomainAccountInfo(info, &domainAccountInfo);
    EXPECT_EQ(info.serverConfigId_, "testConfigId");
    EXPECT_EQ(info.domain_, "testDomain");
    EXPECT_EQ(info.accountName_, "testName");
    EXPECT_EQ(info.accountId_, "testAccountId");
    EXPECT_EQ(info.additionInfo_, "testExtra");
    EXPECT_EQ(info.isAuthenticated, true);
    EXPECT_EQ(domainAccountInfo, nullptr);
}

/**
 * @tc.name: DomainPluginAdapterTest_GetAndCleanPluginAuthResultInfo_003
 * @tc.desc: GetAndCleanPluginAuthResultInfo normal case.
 * @tc.type: FUNC
 * @tc.cover: lines 318-324
 * @tc.require:
 */
HWTEST_F(DomainPluginAdapterTest, DomainPluginAdapterTest_GetAndCleanPluginAuthResultInfo_003, TestSize.Level3)
{
    DomainAuthResult result;
    DomainPluginAdapter::GetAndCleanPluginAuthResultInfo(nullptr, result);
    PluginAuthResultInfo* authResultInfo1 = nullptr;
    DomainPluginAdapter::GetAndCleanPluginAuthResultInfo(&authResultInfo1, result);
    PluginAuthResultInfo* authResultInfo = (PluginAuthResultInfo*)malloc(sizeof(PluginAuthResultInfo));
    ASSERT_NE(authResultInfo, nullptr);
    authResultInfo->freezingTime = 100;
    authResultInfo->remainTimes = 5;
    authResultInfo->nextPhaseFreezingTime = 200;
    authResultInfo->localId = 1001;
    authResultInfo->accountToken.data = nullptr;
    authResultInfo->accountToken.capacity = 0;
    authResultInfo->accountToken.size = 0;
    DomainPluginAdapter::GetAndCleanPluginAuthResultInfo(&authResultInfo, result);
    EXPECT_EQ(result.authStatusInfo.freezingTime, 100);
    EXPECT_EQ(result.authStatusInfo.remainingTimes, 5);
    EXPECT_EQ(result.authStatusInfo.nextPhaseFreezingTime, 200);
    EXPECT_EQ(result.accountId, 1001);
    EXPECT_EQ(authResultInfo, nullptr);
}

/**
 * @tc.name: DomainPluginAdapterTest_ParsePluginConfigInfoList_001
 * @tc.desc: ParsePluginConfigInfoList with nullptr configInfoList.
 * @tc.type: FUNC
 * @tc.cover: lines 372-374
 * @tc.require:
 */
HWTEST_F(DomainPluginAdapterTest, DomainPluginAdapterTest_ParsePluginConfigInfoList_001, TestSize.Level3)
{
    std::vector<DomainServerConfig> configs;
    DomainPluginAdapter::ParsePluginConfigInfoList(nullptr, configs);
    EXPECT_EQ(configs.size(), 0);
}

/**
 * @tc.name: DomainPluginAdapterTest_ParsePluginConfigInfoList_002
 * @tc.desc: ParsePluginConfigInfoList with size 0.
 * @tc.type: FUNC
 * @tc.cover: lines 376-379
 * @tc.require:
 */
HWTEST_F(DomainPluginAdapterTest, DomainPluginAdapterTest_ParsePluginConfigInfoList_002, TestSize.Level3)
{
    PluginServerConfigInfoList* configInfoList = new PluginServerConfigInfoList();
    configInfoList->size = 0;
    configInfoList->items = nullptr;
    std::vector<DomainServerConfig> configs;
    DomainPluginAdapter::ParsePluginConfigInfoList(configInfoList, configs);
    EXPECT_EQ(configs.size(), 0);
}

/**
 * @tc.name: DomainPluginAdapterTest_ParsePluginConfigInfoList_003
 * @tc.desc: ParsePluginConfigInfoList with id failed.
 * @tc.type: FUNC
 * @tc.cover: lines 384-387
 * @tc.require:
 */
HWTEST_F(DomainPluginAdapterTest, DomainPluginAdapterTest_ParsePluginConfigInfoList_003, TestSize.Level3)
{
    PluginServerConfigInfoList* configInfoList = new PluginServerConfigInfoList();
    configInfoList->size = 1;
    configInfoList->items = new PluginServerConfigInfo[1];
    configInfoList->items[0].id.data = nullptr;
    configInfoList->items[0].id.length = 0;
    configInfoList->items[0].domain.data = strdup("testDomain");
    configInfoList->items[0].domain.length = strlen("testDomain");
    configInfoList->items[0].parameters.data = strdup("testParams");
    configInfoList->items[0].parameters.length = strlen("testParams");
    std::vector<DomainServerConfig> configs;
    DomainPluginAdapter::ParsePluginConfigInfoList(configInfoList, configs);
    EXPECT_EQ(configs.size(), 0);
}

/**
 * @tc.name: DomainPluginAdapterTest_ParsePluginConfigInfoList_004
 * @tc.desc: ParsePluginConfigInfoList with domain failed.
 * @tc.type: FUNC
 * @tc.cover: lines 390-391
 * @tc.require:
 */
HWTEST_F(DomainPluginAdapterTest, DomainPluginAdapterTest_ParsePluginConfigInfoList_004, TestSize.Level3)
{
    PluginServerConfigInfoList* configInfoList = new PluginServerConfigInfoList();
    configInfoList->size = 1;
    configInfoList->items = new PluginServerConfigInfo[1];
    configInfoList->items[0].id.data = strdup("testId");
    configInfoList->items[0].id.length = strlen("testId");
    configInfoList->items[0].domain.data = nullptr;
    configInfoList->items[0].domain.length = 0;
    configInfoList->items[0].parameters.data = strdup("testParams");
    configInfoList->items[0].parameters.length = strlen("testParams");
    std::vector<DomainServerConfig> configs;
    DomainPluginAdapter::ParsePluginConfigInfoList(configInfoList, configs);
    EXPECT_EQ(configs.size(), 0);
}

/**
 * @tc.name: DomainPluginAdapterTest_ParsePluginConfigInfoList_005
 * @tc.desc: ParsePluginConfigInfoList with parameters failed.
 * @tc.type: FUNC
 * @tc.cover: lines 394-396
 * @tc.require:
 */
HWTEST_F(DomainPluginAdapterTest, DomainPluginAdapterTest_ParsePluginConfigInfoList_005, TestSize.Level3)
{
    PluginServerConfigInfoList* configInfoList = new PluginServerConfigInfoList();
    configInfoList->size = 1;
    configInfoList->items = new PluginServerConfigInfo[1];
    configInfoList->items[0].id.data = strdup("testId");
    configInfoList->items[0].id.length = strlen("testId");
    configInfoList->items[0].domain.data = strdup("testDomain");
    configInfoList->items[0].domain.length = strlen("testDomain");
    configInfoList->items[0].parameters.data = nullptr;
    configInfoList->items[0].parameters.length = 0;
    std::vector<DomainServerConfig> configs;
    DomainPluginAdapter::ParsePluginConfigInfoList(configInfoList, configs);
    EXPECT_EQ(configs.size(), 0);
}

/**
 * @tc.name: DomainPluginAdapterTest_ParsePluginConfigInfoList_006
 * @tc.desc: ParsePluginConfigInfoList normal case.
 * @tc.type: FUNC
 * @tc.cover: lines 381-401
 * @tc.require:
 */
HWTEST_F(DomainPluginAdapterTest, DomainPluginAdapterTest_ParsePluginConfigInfoList_006, TestSize.Level3)
{
    PluginServerConfigInfoList* configInfoList = new PluginServerConfigInfoList();
    configInfoList->size = 2;
    configInfoList->items = new PluginServerConfigInfo[2];
    configInfoList->items[0].id.data = strdup("testId1");
    configInfoList->items[0].id.length = strlen("testId1");
    configInfoList->items[0].domain.data = strdup("testDomain1");
    configInfoList->items[0].domain.length = strlen("testDomain1");
    configInfoList->items[0].parameters.data = strdup("testParams1");
    configInfoList->items[0].parameters.length = strlen("testParams1");
    configInfoList->items[1].id.data = strdup("testId2");
    configInfoList->items[1].id.length = strlen("testId2");
    configInfoList->items[1].domain.data = strdup("testDomain2");
    configInfoList->items[1].domain.length = strlen("testDomain2");
    configInfoList->items[1].parameters.data = strdup("testParams2");
    configInfoList->items[1].parameters.length = strlen("testParams2");
    std::vector<DomainServerConfig> configs;
    DomainPluginAdapter::ParsePluginConfigInfoList(configInfoList, configs);
    EXPECT_EQ(configs.size(), 2);
    EXPECT_EQ(configs[0].id_, "testId1");
    EXPECT_EQ(configs[0].domain_, "testDomain1");
    EXPECT_EQ(configs[0].parameters_, "testParams1");
    EXPECT_EQ(configs[1].id_, "testId2");
    EXPECT_EQ(configs[1].domain_, "testDomain2");
    EXPECT_EQ(configs[1].parameters_, "testParams2");
}