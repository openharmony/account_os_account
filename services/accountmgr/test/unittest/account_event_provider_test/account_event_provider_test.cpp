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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "account_event_provider.h"
#include "account_error_no.h"
#include "account_log_wrapper.h"
#ifdef HAS_CES_PART
#include "common_event_manager.h"
#include "common_event_support.h"
#endif

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;
#ifdef HAS_CES_PART
using namespace OHOS::EventFwk;
#endif

namespace {
constexpr int32_t DEFAULT_USER_ID = 100;
}

class AccountEventProviderTest : public testing::Test {
public:

    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AccountEventProviderTest::SetUpTestCase() {}

void AccountEventProviderTest::TearDownTestCase() {}

void AccountEventProviderTest::SetUp(){}

void AccountEventProviderTest::TearDown() {}

/**
 * @tc.name: AccountEventProviderTest001
 * @tc.desc: Test account EventPublish interface
 * @tc.type: FUNC
 * @tc.require: #I40129
 */
HWTEST_F(AccountEventProviderTest, AccountEventProviderTest001, TestSize.Level0)
{
#ifdef HAS_CES_PART
    bool ret = AccountEventProvider::EventPublish(
        EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGOFF, DEFAULT_USER_ID);
    EXPECT_EQ(true, ret);
#endif // HAS_CES_PART
}
