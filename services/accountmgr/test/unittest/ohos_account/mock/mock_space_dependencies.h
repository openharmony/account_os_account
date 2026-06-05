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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_TEST_UNITTEST_OHOS_ACCOUNT_MOCK_MOCK_SPACE_DEPENDENCIES_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_TEST_UNITTEST_OHOS_ACCOUNT_MOCK_MOCK_SPACE_DEPENDENCIES_H

#include <vector>
#include <string>
#include "account_error_no.h"
#include "account_info.h"
#include "os_account_info.h"
#include "sub_profile_context.h"

namespace OHOS {
namespace AccountSA {

void ResetMockState();
void MockSetCallingUid(int32_t uid);
void MockSetCallingUserId(int32_t userId);
void MockSetCreatedOsAccounts(const std::vector<OsAccountInfo> &accounts);
void MockForceUpdateSubspaceInfoFail(ErrCode errCode);
void MockForceGetOsAccountInfoByIdFail(ErrCode errCode);
void MockForceReadSubProfileContextFail(ErrCode errCode);
void MockClearForceFailFlags();
void MockForceSubProfileContext(int32_t localId, const SubProfileContext &data);
void MockInsertForegroundSubspaceId(int32_t localId, int32_t subspaceId);
void MockEraseForegroundSubspaceId(int32_t localId);
bool MockFindForegroundSubspaceId(int32_t localId, int32_t &subspaceId);
std::string GenerateOhosUdidWithSha256(const std::string &name, const std::string &uid);

} // namespace AccountSA
} // namespace OHOS

#endif
