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

#include "inner_authorization_manager.h"

#include <map>
#include <mutex>
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "authorization_common.h"
#include "iauthorization_callback.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AccountSA {
namespace {
std::mutex g_mutex;
static std::map<int32_t, std::shared_ptr<ConnectAbilityCallback>> g_callbackMap;
}

ConnectAbilityCallback::ConnectAbilityCallback(int32_t callingPid,
    const sptr<IRemoteObject> &authorizationResultCallback, const AuthorizationResult &result)
{
    authorizationResultCallback_ = authorizationResultCallback;
    result_ = result;
    callingPid_ = callingPid;
}

ErrCode ConnectAbilityCallback::OnResult(int32_t resultCode, const std::vector<uint8_t> &iamToken)
{
    ACCOUNT_LOGI("ConnectAbilityCallback OnResult resultCode:%{public}d", resultCode);
    auto callback = iface_cast<IAuthorizationCallback>(authorizationResultCallback_);
    callback->OnResult(ERR_OK, result_);
    return ERR_OK;
}

InnerAuthorizationManager &InnerAuthorizationManager::GetInstance()
{
    static InnerAuthorizationManager instance;
    return instance;
}

InnerAuthorizationManager::InnerAuthorizationManager()
{}

InnerAuthorizationManager::~InnerAuthorizationManager()
{}

ErrCode InnerAuthorizationManager::AcquireAuthorization(const std::string &privilege,
    const AcquireAuthorizationOptions &options, const sptr<IRemoteObject> &authorizationResultCallback)
{
    ACCOUNT_LOGI("AcquireAuthorization privilege:%{public}s", privilege.c_str());
    std::lock_guard<std::mutex> lock(g_mutex);
    AuthorizationResult result;
    int32_t callingPid = IPCSkeleton::GetCallingPid();
    auto connectCallback = std::make_shared<ConnectAbilityCallback>(callingPid, authorizationResultCallback, result);
    g_callbackMap.emplace(callingPid, connectCallback);
    ConnectAbilityInfo info;
    auto callback = iface_cast<IAuthorizationCallback>(authorizationResultCallback);
    callback->OnConnectAbility(info, connectCallback->AsObject());
    return ERR_OK;
}
}
}
