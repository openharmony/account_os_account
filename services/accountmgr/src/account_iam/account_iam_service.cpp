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

#include "account_iam_service.h"

#include "account_log_wrapper.h"
#include "account_permission_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AccountSA {
namespace {
#ifdef HAS_STORAGE_PART
const int32_t ERROR_STORAGE_KEY_NOT_EXIST = -2;
#endif
}

AccountIAMService::AccountIAMService()
{}

AccountIAMService::~AccountIAMService()
{}

ErrCode AccountIAMService::ActivateUserKey(
    int32_t userId, const std::vector<uint8_t> &token, const std::vector<uint8_t> &secret)
{
    ACCOUNT_LOGD("enter");
#ifdef HAS_STORAGE_PART
    ErrCode result = GetStorageManagerProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGD("fail to get storage proxy");
        return result;
    }
    result = storageMgrProxy_->ActiveUserKey(userId, token, secret);
    if (result != ERR_OK && result != ERROR_STORAGE_KEY_NOT_EXIST) {
        ACCOUNT_LOGD("fail to active user key, error code: %{public}d", result);
        return result;
    }
    storageMgrProxy_->PrepareStartUser(userId);
#endif
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = credInfoMap_.find(userId);
    if (it != credInfoMap_.end()) {
        it->second.secret = secret;
    } else {
        credInfoMap_[userId] = {
            .secret = secret
        };
    }
    return ERR_OK;
}

ErrCode AccountIAMService::UpdateUserKey(int32_t userId, uint64_t credentialId,
    const std::vector<uint8_t> &token, const std::vector<uint8_t> &newSecret)
{
    ACCOUNT_LOGD("enter");
    ErrCode result = ERR_OK;
    CredentialInfo oldCredInfo;
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = credInfoMap_.find(userId);
    if (it != credInfoMap_.end()) {
        oldCredInfo = it->second;
    }
    if (newSecret.empty() && credentialId != oldCredInfo.credentialId) {
        ACCOUNT_LOGD("the key do not need to be removed");
        return ERR_OK;
    }
#ifdef HAS_STORAGE_PART
    result = GetStorageManagerProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGD("fail to get storage proxy");
        return result;
    }
    result = storageMgrProxy_->UpdateUserAuth(userId, token, oldCredInfo.secret, newSecret);
    if (result != ERR_OK && result != ERROR_STORAGE_KEY_NOT_EXIST) {
        ACCOUNT_LOGD("fail to update user auth");
        return result;
    }
    result = storageMgrProxy_->UpdateKeyContext(userId);
#endif
    credInfoMap_[userId] = {
        .credentialId = credentialId,
        .oldSecret = oldCredInfo.secret,
        .secret = newSecret
    };
    return result;
}

ErrCode AccountIAMService::RemoveUserKey(int32_t userId, const std::vector<uint8_t> &token)
{
    ACCOUNT_LOGD("enter");
    ErrCode result = ERR_OK;
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = credInfoMap_.find(userId);
    if (it == credInfoMap_.end()) {
        return ERR_OK;
    }
    CredentialInfo oldCredInfo = it->second;
    std::vector<uint8_t> newSecret;
#ifdef HAS_STORAGE_PART
    result = GetStorageManagerProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGD("fail to get storage proxy");
        return result;
    }
    result = storageMgrProxy_->UpdateUserAuth(userId, token, oldCredInfo.secret, newSecret);
    if (result != ERR_OK && result != ERROR_STORAGE_KEY_NOT_EXIST) {
        ACCOUNT_LOGD("fail to update user auth");
        return result;
    }
    result = storageMgrProxy_->UpdateKeyContext(userId);
#endif
    credInfoMap_[userId] = {
        .oldSecret = oldCredInfo.secret,
        .secret = newSecret
    };
    return result;
}

ErrCode AccountIAMService::RestoreUserKey(int32_t userId, uint64_t credentialId,
    const std::vector<uint8_t> &token)
{
    ACCOUNT_LOGD("enter");
    ErrCode result = ERR_OK;
    CredentialInfo credInfo;
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = credInfoMap_.find(userId);
    if (it != credInfoMap_.end()) {
        credInfo = it->second;
    }
    if (credentialId != 0 && credInfo.credentialId != credentialId) {
        return ERR_OK;
    }
#ifdef HAS_STORAGE_PART
    result = GetStorageManagerProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGD("fail to get storage proxy");
        return result;
    }
    result = storageMgrProxy_->UpdateUserAuth(userId, token, credInfo.secret, credInfo.oldSecret);
    if (result != ERR_OK && result != ERROR_STORAGE_KEY_NOT_EXIST) {
        ACCOUNT_LOGD("fail to update user auth");
        return result;
    }
    result = storageMgrProxy_->UpdateKeyContext(userId);
#endif
    credInfoMap_[userId] = {
        .secret = credInfo.oldSecret
    };
    return result;
}

#ifdef HAS_STORAGE_PART
ErrCode AccountIAMService::GetStorageManagerProxy()
{
    ACCOUNT_LOGD("enter");
    if (storageMgrProxy_ != nullptr) {
        return ERR_OK;
    }
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        ACCOUNT_LOGD("failed to get system ability mgr");
        return ERR_ACCOUNT_IAM_SERVICE_GET_STORAGE_SYSTEM_ABILITY;
    }
    auto remote = systemAbilityManager->GetSystemAbility(STORAGE_MANAGER_MANAGER_ID);
    if (!remote) {
        ACCOUNT_LOGD("failed to get STORAGE_MANAGER_MANAGER_ID service");
        return ERR_ACCOUNT_IAM_SERVICE_REMOTE_IS_NULLPTR;
    }
    storageMgrProxy_ = iface_cast<StorageManager::IStorageManager>(remote);
    if (!storageMgrProxy_) {
        ACCOUNT_LOGD("failed to get STORAGE_MANAGER_MANAGER_ID proxy");
        return ERR_ACCOUNT_IAM_SERVICE_REMOTE_IS_NULLPTR;
    }
    return ERR_OK;
}
#endif
}  // namespace AccountSA
}  // namespace OHOS
