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

#include "taihe_authorization_callback_base.h"
#include "account_log_wrapper.h"
#include <thread>

namespace OHOS {
namespace AccountSA {

ErrCode NotifyAuthorizationResultWithRetry(const sptr<IRemoteObject>& callback, int32_t errCode,
    const std::vector<uint8_t> &iamToken, int32_t accountId, int32_t resultCode)
{
    auto connectCallback = iface_cast<IConnectAbilityCallback>(callback);
    if (connectCallback == nullptr) {
        ACCOUNT_LOGE("ConnectAbilityCallback proxy is nullptr");
        return ERR_AUTHORIZATION_CREATE_UI_EXTENSION_ERROR;
    }
    ErrCode ret = ERR_OK;
    int retryTimes = 0;
    while (retryTimes < Constants::MAX_RETRY_TIMES) {
        ret = connectCallback->OnResult(errCode, iamToken, accountId, resultCode);
        if (ret == ERR_OK || (ret != Constants::E_IPC_ERROR && ret != Constants::E_IPC_SA_DIED)) {
            break;
        }
        retryTimes++;
        ACCOUNT_LOGE("Send OnResult failed, code=%{public}d, retryTimes=%{public}d", ret, retryTimes);
        std::this_thread::sleep_for(std::chrono::milliseconds(Constants::DELAY_FOR_EXCEPTION));
    }
    return ret;
}

} // namespace AccountSA
} // namespace OHOS
