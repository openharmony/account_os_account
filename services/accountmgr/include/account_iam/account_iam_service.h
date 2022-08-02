/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_IAM_SERVICE_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_IAM_SERVICE_H

#include <vector>
#include "account_iam_stub.h"
#include "account_error_no.h"
#ifdef HAS_STORAGE_PART
#include "istorage_manager.h"
#include "storage_manager.h"
#include "storage_manager_proxy.h"
#endif

namespace OHOS {
namespace AccountSA {
struct CredentialInfo {
    uint64_t credentialId = 0;
    std::vector<uint8_t> oldSecret;
    std::vector<uint8_t> secret;
};

class AccountIAMService : public AccountIAMStub {
public:
    AccountIAMService();
    ~AccountIAMService() override;

    ErrCode ActivateUserKey(
        int32_t userId, const std::vector<uint8_t> &token, const std::vector<uint8_t> &secret) override;
    ErrCode UpdateUserKey(int32_t userId, uint64_t credentialId,
        const std::vector<uint8_t> &token, const std::vector<uint8_t> &newSecret) override;
    ErrCode RemoveUserKey(int32_t userId, const std::vector<uint8_t> &token) override;
    ErrCode RestoreUserKey(int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &token) override;

private:
    ErrCode GetStorageManagerProxy();

private:
#ifdef HAS_STORAGE_PART
    sptr<StorageManager::IStorageManager> storageMgrProxy_;
#endif
    std::mutex mutex_;
    std::map<int32_t, CredentialInfo> credInfoMap_;
    DISALLOW_COPY_AND_MOVE(AccountIAMService);
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_IAM_SERVICE_H
