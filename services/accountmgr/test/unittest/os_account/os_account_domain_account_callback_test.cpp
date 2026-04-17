/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
#include "os_account_control_file_manager.h"
#include "os_account_domain_account_callback.h"
#include "os_account_info.h"
#undef private
#include "parcel.h"
using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
} // namespace

class DomainAccountCallbackTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DomainAccountCallbackTest::SetUpTestCase(void)
{}

void DomainAccountCallbackTest::TearDownTestCase(void)
{}

void DomainAccountCallbackTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void DomainAccountCallbackTest::TearDown(void)
{}

/**
 * @tc.name: DomainPluginStubModuleTest_OnResult_001
 * @tc.desc: OnResult with callback is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountCallbackTest, DomainAccountCallbackTest_OnResult_001, TestSize.Level3)
{
    CreateOsAccountForDomainOptions accountOptions;
    std::shared_ptr<IOsAccountControl> testOsAccountControl = nullptr;
    auto callbackPtr = std::make_shared<CheckAndCreateDomainAccountCallback>(testOsAccountControl,
        OsAccountType::NORMAL, nullptr, accountOptions);
    Parcel parcel;
    DomainAccountParcel domainAccountParcel;
    domainAccountParcel.SetParcelData(parcel);
    callbackPtr->OnResult(0, domainAccountParcel);
    EXPECT_EQ(callbackPtr->innerCallback_, nullptr);
}

/**
 * @tc.name: DomainPluginStubModuleTest_OnResult_002
 * @tc.desc: OnResult with callback is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountCallbackTest, DomainAccountCallbackTest_OnResult_002, TestSize.Level3)
{
    OsAccountInfo osAccountInfo;
    std::shared_ptr<IOsAccountControl> testOsAccountControl = nullptr;
    auto callbackPtr = std::make_shared<BindDomainAccountCallback>(testOsAccountControl, osAccountInfo, nullptr);
    Parcel parcel;
    callbackPtr->OnResult(0, parcel);
    EXPECT_EQ(callbackPtr->innerCallback_, nullptr);
}

/**
 * @tc.name: DomainAccountCallbackTest_OnResult_003
 * @tc.desc: CheckAndCreateDomainAccountCallback::OnResult with non-zero errCode and null innerCallback
 *           returns ERR_OK due to the null callback early-exit guard.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountCallbackTest, DomainAccountCallbackTest_OnResult_003, TestSize.Level3)
{
    CreateOsAccountForDomainOptions accountOptions;
    std::shared_ptr<IOsAccountControl> testOsAccountControl = nullptr;
    auto callbackPtr = std::make_shared<CheckAndCreateDomainAccountCallback>(testOsAccountControl,
        OsAccountType::NORMAL, nullptr, accountOptions);
    Parcel parcel;
    DomainAccountParcel domainAccountParcel;
    domainAccountParcel.SetParcelData(parcel);

    // Non-zero errCode: null-check guard fires first, returns ERR_OK without calling HandleErrorWithEmptyResult
    ErrCode ret = callbackPtr->OnResult(ERR_ACCOUNT_COMMON_INVALID_PARAMETER, domainAccountParcel);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(callbackPtr->innerCallback_, nullptr);
}

/**
 * @tc.name: DomainAccountCallbackTest_OnResult_004
 * @tc.desc: BindDomainAccountCallback::OnResult with non-zero errCode and null innerCallback returns
 *           without crashing due to the null callback early-exit guard.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountCallbackTest, DomainAccountCallbackTest_OnResult_004, TestSize.Level3)
{
    OsAccountInfo osAccountInfo;
    std::shared_ptr<IOsAccountControl> testOsAccountControl = nullptr;
    auto callbackPtr = std::make_shared<BindDomainAccountCallback>(testOsAccountControl, osAccountInfo, nullptr);
    Parcel parcel;

    // Non-zero errCode: null-check guard fires first, returns without accessing osAccountControl_ or innerCallback_
    callbackPtr->OnResult(ERR_ACCOUNT_COMMON_INVALID_PARAMETER, parcel);
    EXPECT_EQ(callbackPtr->innerCallback_, nullptr);
}

/**
 * @tc.name: DomainAccountCallbackTest_OnResult_005
 * @tc.desc: CheckAndCreateDomainAccountCallback with ADMIN type and null innerCallback returns ERR_OK.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountCallbackTest, DomainAccountCallbackTest_OnResult_005, TestSize.Level3)
{
    CreateOsAccountForDomainOptions accountOptions;
    std::shared_ptr<IOsAccountControl> testOsAccountControl = nullptr;

    // Test with ADMIN type
    auto callbackAdmin = std::make_shared<CheckAndCreateDomainAccountCallback>(testOsAccountControl,
        OsAccountType::ADMIN, nullptr, accountOptions);
    Parcel parcel;
    DomainAccountParcel domainAccountParcel;
    domainAccountParcel.SetParcelData(parcel);
    ErrCode ret = callbackAdmin->OnResult(0, domainAccountParcel);
    EXPECT_EQ(ret, ERR_OK);

    // Test with GUEST type
    auto callbackGuest = std::make_shared<CheckAndCreateDomainAccountCallback>(testOsAccountControl,
        OsAccountType::GUEST, nullptr, accountOptions);
    ret = callbackGuest->OnResult(0, domainAccountParcel);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: DomainAccountCallbackTest_OnResult_006
 * @tc.desc: BindDomainAccountCallback with various OsAccountInfo and null innerCallback: verifies
 *           that multiple consecutive OnResult calls with errCode=0 do not crash.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountCallbackTest, DomainAccountCallbackTest_OnResult_006, TestSize.Level3)
{
    std::shared_ptr<IOsAccountControl> testOsAccountControl = nullptr;

    // OsAccountInfo with localId = START_USER_ID should trigger the special branch
    OsAccountInfo startUserInfo;
    startUserInfo.SetLocalId(Constants::START_USER_ID);
    auto callbackStart = std::make_shared<BindDomainAccountCallback>(testOsAccountControl, startUserInfo, nullptr);
    Parcel parcel;
    callbackStart->OnResult(0, parcel);
    EXPECT_EQ(callbackStart->innerCallback_, nullptr);

    // OsAccountInfo with a regular localId
    OsAccountInfo regularInfo;
    regularInfo.SetLocalId(1001);
    auto callbackRegular = std::make_shared<BindDomainAccountCallback>(testOsAccountControl, regularInfo, nullptr);
    callbackRegular->OnResult(0, parcel);
    EXPECT_EQ(callbackRegular->innerCallback_, nullptr);
}