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

#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE

#include <gtest/gtest.h>

#define private public
#include "account_mgr_service.h"
#undef private

#include "account_error_no.h"
#include "account_info.h"
#include "account_log_wrapper.h"
#include "account_test_common.h"
#include "accesstoken_kit.h"
#include "os_account_subspace_manager_service.h"
#include "iinner_os_account_manager.h"
#include "os_account_constants.h"
#include "token_setproc.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;
using namespace OHOS::Security::AccessToken;

namespace {
constexpr int32_t TEST_OS_ACCOUNT_ID = 100;
constexpr int32_t TEST_SUBSPACE_ID_BASE = 100000;
constexpr uid_t ROOT_UID = 0;
constexpr uid_t TEST_UID = 100;
}  // namespace

class OsAccountSubspaceServiceTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        allPermTokenId_ = GetAllAccountPermission();
        ASSERT_NE(allPermTokenId_, 0);
        service_ = std::make_shared<OsAccountSubspaceManagerService>();
        accountMgrService_ = std::make_shared<AccountMgrService>();
    }

    static void TearDownTestCase()
    {
        accountMgrService_.reset();
        service_.reset();
        if (allPermTokenId_ != 0) {
            AccessTokenKit::DeleteToken(static_cast<AccessTokenID>(allPermTokenId_));
        }
    }

    void SetUp() override
    {
        ASSERT_EQ(SetSelfTokenID(allPermTokenId_), 0);
    }

    void TearDown() override {}

    static std::shared_ptr<OsAccountSubspaceManagerService> service_;
    static std::shared_ptr<AccountMgrService> accountMgrService_;
    static uint64_t allPermTokenId_;
};

std::shared_ptr<OsAccountSubspaceManagerService> OsAccountSubspaceServiceTest::service_ = nullptr;
std::shared_ptr<AccountMgrService> OsAccountSubspaceServiceTest::accountMgrService_ = nullptr;
uint64_t OsAccountSubspaceServiceTest::allPermTokenId_ = 0;

/**
 * @tc.name: CreateOsAccountSubspace_CheckUserIdValid_001
 * @tc.desc: C6/C5 - CheckUserIdValid blocks system-reserved IDs (0, 50, 99, START_USER_ID-1)
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceServiceTest, CreateOsAccountSubspace_CheckUserIdValid_001, TestSize.Level1)
{
    EXPECT_EQ(accountMgrService_->CheckUserIdValid(0), ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR);
    EXPECT_EQ(accountMgrService_->CheckUserIdValid(50), ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR);
    int32_t reservedId = Constants::START_USER_ID - 1;
    EXPECT_EQ(accountMgrService_->CheckUserIdValid(reservedId), ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR);
    EXPECT_EQ(accountMgrService_->CheckUserIdValid(99), ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR);
}

/**
 * @tc.name: DeleteOsAccountSubspace_OwnershipMismatch_001
 * @tc.desc: R3 - Ownership mismatch returns SUBSPACE_NOT_FOUND (distId/1000 != osAccountId)
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceServiceTest, DeleteOsAccountSubspace_OwnershipMismatch_001, TestSize.Level1)
{
    int32_t wrongDistId = 200001;
    ErrCode ret = service_->DeleteOsAccountSubspace(TEST_OS_ACCOUNT_ID, wrongDistId);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND);
}

/**
 * @tc.name: DeleteOsAccountSubspace_RemoveZeroSubspace_002
 * @tc.desc: R5 - Cannot remove 0-index space (distId % 1000 == 0) returns SUBSPACE_RESTRICTED
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceServiceTest, DeleteOsAccountSubspace_RemoveZeroSubspace_002, TestSize.Level1)
{
    ErrCode ret = service_->DeleteOsAccountSubspace(TEST_OS_ACCOUNT_ID, TEST_SUBSPACE_ID_BASE);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_RESTRICTED);
}

/**
 * @tc.name: SwitchOsAccountSubspace_OwnershipMismatch_001
 * @tc.desc: S3 - Ownership mismatch returns SUBSPACE_NOT_FOUND
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceServiceTest, SwitchOsAccountSubspace_OwnershipMismatch_001, TestSize.Level1)
{
    int32_t wrongDistId = 200001;
    ErrCode ret = service_->SwitchOsAccountSubspace(TEST_OS_ACCOUNT_ID, wrongDistId);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND);
}

/**
 * @tc.name: CreateOsAccountSubspace_PermissionDenied_002
 * @tc.desc: C4 - CreateOsAccountSubspace full business API rejects non-system-app caller.
 *            Permission check runs first in Service layer and returns early,
 *            not penetrating to uninitialized Manager layer.
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceServiceTest, CreateOsAccountSubspace_PermissionDenied_002, TestSize.Level1)
{
    uint64_t noPermTokenId = 0;
    ASSERT_TRUE(AllocPermission({}, noPermTokenId, false));
    ASSERT_EQ(SetSelfTokenID(noPermTokenId), 0);
    setuid(TEST_UID);
    OsAccountSubspaceResult result;
    ErrCode ret = service_->CreateOsAccountSubspace(TEST_OS_ACCOUNT_ID, result);
    EXPECT_NE(ret, ERR_OK);
    setuid(ROOT_UID);
    ASSERT_TRUE(RecoveryPermission(noPermTokenId, allPermTokenId_));
}

/**
 * @tc.name: CreateOsAccountSubspace_AdminAccount_001
 * @tc.desc: Create: osAccountId=0 (ADMIN) → CheckLocalIdRestricted → MANAGER_ID_ERROR (12300008)
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceServiceTest, CreateOsAccountSubspace_AdminAccount_001, TestSize.Level1)
{
    OsAccountSubspaceResult result;
    ErrCode ret = service_->CreateOsAccountSubspace(0, result);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR);
}

/**
 * @tc.name: CreateOsAccountSubspace_AccountNotFound_001
 * @tc.desc: Create: osAccountId=200 (nonexistent, >=100) → GetOsAccountInfoById fails → NOT_EXIST (12300003)
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceServiceTest, CreateOsAccountSubspace_AccountNotFound_001, TestSize.Level1)
{
    OsAccountSubspaceResult result;
    ErrCode ret = service_->CreateOsAccountSubspace(200, result);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: DeleteOsAccountSubspace_PermissionDenied_001
 * @tc.desc: R3 - DeleteOsAccountSubspace full business API rejects non-system-app caller.
 *            Permission check runs first and returns early.
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceServiceTest, DeleteOsAccountSubspace_PermissionDenied_001, TestSize.Level1)
{
    uint64_t noPermTokenId = 0;
    ASSERT_TRUE(AllocPermission({}, noPermTokenId, false));
    ASSERT_EQ(SetSelfTokenID(noPermTokenId), 0);
    setuid(TEST_UID);
    ErrCode ret = service_->DeleteOsAccountSubspace(TEST_OS_ACCOUNT_ID, TEST_SUBSPACE_ID_BASE + 1);
    EXPECT_NE(ret, ERR_OK);
    setuid(ROOT_UID);
    ASSERT_TRUE(RecoveryPermission(noPermTokenId, allPermTokenId_));
}

/**
 * @tc.name: SwitchOsAccountSubspace_PermissionDenied_001
 * @tc.desc: S3 - SwitchOsAccountSubspace full business API rejects non-system-app caller.
 *            Permission check runs first and returns early.
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceServiceTest, SwitchOsAccountSubspace_PermissionDenied_001, TestSize.Level1)
{
    uint64_t noPermTokenId = 0;
    ASSERT_TRUE(AllocPermission({}, noPermTokenId, false));
    ASSERT_EQ(SetSelfTokenID(noPermTokenId), 0);
    setuid(TEST_UID);
    ErrCode ret = service_->SwitchOsAccountSubspace(TEST_OS_ACCOUNT_ID, TEST_SUBSPACE_ID_BASE + 1);
    EXPECT_NE(ret, ERR_OK);
    setuid(ROOT_UID);
    ASSERT_TRUE(RecoveryPermission(noPermTokenId, allPermTokenId_));
}

/**
 * @tc.name: DeleteOsAccountSubspace_NegativeSubspaceId_001
 * @tc.desc: R3 - Negative subspaceId causes ownership mismatch (subspaceId/1000 != osAccountId)
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceServiceTest, DeleteOsAccountSubspace_NegativeSubspaceId_001, TestSize.Level1)
{
    ErrCode ret = service_->DeleteOsAccountSubspace(TEST_OS_ACCOUNT_ID, -1);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND);
}

/**
 * @tc.name: DeleteOsAccountSubspace_ZeroIndexOwnershipMismatch_001
 * @tc.desc: R5/R3 - subspaceId=0 (0/1000=0 != 100) causes ownership mismatch;
 *            ownership check runs before 0-index RESTRICTED check, returns SUBSPACE_NOT_FOUND
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceServiceTest, DeleteOsAccountSubspace_ZeroIndexOwnershipMismatch_001, TestSize.Level1)
{
    ErrCode ret = service_->DeleteOsAccountSubspace(TEST_OS_ACCOUNT_ID, 0);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND);
}

/**
 * @tc.name: DeleteOsAccountSubspace_ZeroIndexOwnershipConsistent_001
 * @tc.desc: R5 - When osAccountId=0 (ADMIN_LOCAL_ID), CheckLocalIdRestricted returns non-OK
 *            which maps to SUBSPACE_NOT_FOUND for Delete/Switch.
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceServiceTest, DeleteOsAccountSubspace_ZeroIndexOwnershipConsistent_001, TestSize.Level1)
{
    ErrCode ret = service_->DeleteOsAccountSubspace(0, 0);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND);
}

/**
 * @tc.name: DeleteOsAccountSubspace_OwnershipMismatch_LargeId_001
 * @tc.desc: R3 - subspaceId far exceeds osAccountId range (999999/1000=999 != 100)
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceServiceTest, DeleteOsAccountSubspace_OwnershipMismatch_LargeId_001, TestSize.Level1)
{
    ErrCode ret = service_->DeleteOsAccountSubspace(TEST_OS_ACCOUNT_ID, 999999);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND);
}

/**
 * @tc.name: SwitchOsAccountSubspace_OwnershipMismatch_LargeId_001
 * @tc.desc: S3 - subspaceId far exceeds osAccountId range (999999/1000=999 != 100)
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceServiceTest, SwitchOsAccountSubspace_OwnershipMismatch_LargeId_001, TestSize.Level1)
{
    ErrCode ret = service_->SwitchOsAccountSubspace(TEST_OS_ACCOUNT_ID, 999999);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND);
}
#endif  // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE