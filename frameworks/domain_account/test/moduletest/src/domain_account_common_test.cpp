/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "account_log_wrapper.h"
#define private public
#include "domain_account_common.h"
#undef private
#include "domain_account_client.h"
#include "parcel.h"
#include "want.h"
using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const int32_t CALLING_UID = 100;
const int32_t REMAINING_TIMES = 100;
const std::string STRING_NAME_TWO = "zhangsan666";
const std::string STRING_DOMAIN_NEW = "test.example.com";
const std::string STRING_NAME_NEW = "zhangsan777";
const std::string STRING_ACCOUNTID_NEW = "3333";
const std::vector<uint8_t> TOKEN = {1, 2, 3, 4, 5};
} // namespace

class DomainAccountCommonModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DomainAccountCommonModuleTest::SetUpTestCase(void)
{
    GTEST_LOG_(INFO) << "SetUpTestCase enter";
}

void DomainAccountCommonModuleTest::TearDownTestCase(void)
{
    GTEST_LOG_(INFO) << "TearDownTestCase";
}

void DomainAccountCommonModuleTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void DomainAccountCommonModuleTest::TearDown(void)
{}

/**
 * @tc.name: DomainAccountCommonModuleTest_GetAccessTokenOptions_001
 * @tc.desc: GetAccessTokenOptions Marshalling successfully.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountCommonModuleTest, DomainAccountCommonModuleTest_GetAccessTokenOptions_001, TestSize.Level0)
{
    AAFwk::WantParams parameters;
    GetAccessTokenOptions option(CALLING_UID, parameters);
    Parcel parcel;
    option.Marshalling(parcel);
    GetAccessTokenOptions *getAccessTokenOptions = option.Unmarshalling(parcel);
    std::shared_ptr<GetAccessTokenOptions> optionPtr(getAccessTokenOptions);
    EXPECT_EQ(getAccessTokenOptions->callingUid_, CALLING_UID);
}

/**
 * @tc.name: DomainAccountCommonModuleTest_DomainAuthResult_001
 * @tc.desc: DomainAuthResult Marshalling successfully.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountCommonModuleTest, DomainAccountCommonModuleTest_DomainAuthResult_001, TestSize.Level0)
{
    DomainAuthResult domainAuthResult;
    domainAuthResult.token = TOKEN;
    Parcel parcel;
    domainAuthResult.Marshalling(parcel);
    DomainAuthResult *result = domainAuthResult.Unmarshalling(parcel);
    std::shared_ptr<DomainAuthResult> domainAuthResultPtr(result);
    for (size_t index = 0; index < result->token.size(); index++) {
        EXPECT_EQ(result->token[index], TOKEN[index]);
    }
}

/**
 * @tc.name: DomainAccountCommonModuleTest_AuthStatusInfo_001
 * @tc.desc: AuthStatusInfo Marshalling successfully.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountCommonModuleTest, DomainAccountCommonModuleTest_AuthStatusInfo_001, TestSize.Level0)
{
    AuthStatusInfo authStatusInfo;
    authStatusInfo.remainingTimes = REMAINING_TIMES;
    Parcel parcel;
    authStatusInfo.Marshalling(parcel);
    AuthStatusInfo *result = authStatusInfo.Unmarshalling(parcel);
    std::shared_ptr<AuthStatusInfo> authStatusInfoPtr(result);
    EXPECT_EQ(authStatusInfoPtr->remainingTimes, REMAINING_TIMES);
}

/**
 * @tc.name: DomainAccountCommonModuleTest_DomainServerConfig_001
 * @tc.desc: DomainServerConfig Marshalling successfully.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountCommonModuleTest, DomainAccountCommonModuleTest_DomainServerConfig_001, TestSize.Level0)
{
    std::string parameters;
    string id = STRING_DOMAIN_NEW;
    DomainServerConfig config(parameters, id);
    Parcel parcel;
    config.Marshalling(parcel);
    DomainServerConfig *result = config.Unmarshalling(parcel);
    std::shared_ptr<DomainServerConfig> infoPtr(result);
    EXPECT_EQ(infoPtr->id_, STRING_DOMAIN_NEW);
}