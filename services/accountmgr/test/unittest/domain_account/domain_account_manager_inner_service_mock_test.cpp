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

#include <gtest/gtest.h>
#include "account_error_no.h"
#include "account_log_wrapper.h"
#define private public
#include "inner_domain_account_manager.h"
#undef private
#include "parameters.h"

namespace OHOS {
namespace {
static bool g_isSupportNetRequest = true;
}
namespace system {
bool GetBoolParameter(const std::string& key, bool def)
{
    return g_isSupportNetRequest;
}
}
namespace AccountSA {
using namespace testing;
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS;
using namespace AccountSA;

namespace {
static constexpr int32_t USER_UID = 100 * 200000;
}

class DomainAccountManagerInnerServiceMockTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DomainAccountManagerInnerServiceMockTest::SetUpTestCase(void)
{}

void DomainAccountManagerInnerServiceMockTest::TearDownTestCase(void)
{}

void DomainAccountManagerInnerServiceMockTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void DomainAccountManagerInnerServiceMockTest::TearDown(void)
{}

/**
 * @tc.name: SetAccountPolicy001
 * @tc.desc: Test IsSupportNetRequest.
 * @tc.type: FUNC
 * @tc.require: issueI64KAM
 */
HWTEST_F(DomainAccountManagerInnerServiceMockTest, SetAccountPolicy001, TestSize.Level1)
{
    g_isSupportNetRequest = true;
    DomainAccountInfo domainInfo;
    std::string policy;
    InnerDomainAccountManager *instance = new (std::nothrow) InnerDomainAccountManager();
    std::string rightPath = "/rightPath/";
    std::string rightSoName = "right.z.so";
    // LoadLib success
    instance->LoaderLib(rightPath, rightSoName);
    setuid(USER_UID);
    EXPECT_EQ(instance->SetAccountPolicy(domainInfo, policy),
        ERR_DOMAIN_ACCOUNT_NOT_SUPPORT_BACKGROUND_ACCOUNT_REQUEST);
    EXPECT_EQ(instance->GetAccountPolicy(domainInfo, policy),
        ERR_DOMAIN_ACCOUNT_NOT_SUPPORT_BACKGROUND_ACCOUNT_REQUEST);
}
} // AccountSA
} // OHOS