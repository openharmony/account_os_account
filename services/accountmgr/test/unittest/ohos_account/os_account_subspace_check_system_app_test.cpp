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

#include <gtest/gtest.h>

#include "account_error_no.h"
#include "account_test_common.h"
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "os_account_sub_profile_event_service.h"
#include "os_account_sub_profile_subscribe_callback.h"
#include "os_account_subspace_manager_service.h"
#include "token_setproc.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;
using namespace OHOS::Security::AccessToken;

namespace {
class SubspaceManagerServiceCheckSystemAppTest : public testing::Test {
public:
    void SetUp() override
    {
        oldTokenId_ = IPCSkeleton::GetSelfTokenID();
        uint64_t noPermTokenId = 0;
        ASSERT_TRUE(AllocPermission({}, noPermTokenId, false));
        service_ = sptr<OsAccountSubProfileManagerService>(new (std::nothrow) OsAccountSubProfileManagerService());
        ASSERT_NE(service_, nullptr);
        listener_ = service_;
    }
    void TearDown() override
    {
        listener_ = nullptr;
        service_ = nullptr;
        uint64_t currentToken = IPCSkeleton::GetSelfTokenID();
        ASSERT_TRUE(RecoveryPermission(currentToken, oldTokenId_));
    }
    sptr<OsAccountSubProfileManagerService> service_;
    sptr<IRemoteObject> listener_;
    uint64_t oldTokenId_;
};

HWTEST_F(SubspaceManagerServiceCheckSystemAppTest, Subscribe_NonSystemApp_001, TestSize.Level1)
{
    ErrCode ret = service_->SubscribeOsAccountSubProfileEvents(
        {static_cast<int32_t>(OsAccountSubProfileEventType::CREATED)}, listener_);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR);
}

HWTEST_F(SubspaceManagerServiceCheckSystemAppTest, Unsubscribe_NonSystemApp_001, TestSize.Level1)
{
    ErrCode ret = service_->UnsubscribeOsAccountSubProfileEvents(
        {static_cast<int32_t>(OsAccountSubProfileEventType::CREATED)}, listener_);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR);
}
} // namespace