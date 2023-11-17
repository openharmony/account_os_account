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

#ifndef OS_ACCOUNT_SERVICE_BUNDLE_USER_MANAGER_ADAPTER_PROXY_H
#define OS_ACCOUNT_SERVICE_BUNDLE_USER_MANAGER_ADAPTER_PROXY_H

#include "bundle_framework_core_ipc_interface_code.h"
#include "bundle_user_mgr_interface.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace AccountSA {
class BundleUserManagerAdapterProxy : public IRemoteProxy<AppExecFwk::IBundleUserMgr> {
public:
    explicit BundleUserManagerAdapterProxy(const sptr<IRemoteObject> &object);
    ~BundleUserManagerAdapterProxy() override;

    /**
     * @brief Create new user.
     * @param userId Indicates the userId.
     * @param disallowedHapList Pass in the provisioned disallowList.
     */
    ErrCode CreateNewUser(int32_t userId, const std::vector<std::string> &disallowedHapList = {}) override;
    /**
     * @brief Remove user.
     * @param userId Indicates the userId.
     */
    ErrCode RemoveUser(int32_t userId) override;

private:
    bool SendTransactCmd(AppExecFwk::BundleUserMgrInterfaceCode code, MessageParcel &data, MessageParcel &reply);
    static inline BrokerDelegator<BundleUserManagerAdapterProxy> delegator_;
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_SERVICE_BUNDLE_MANAGER_ADAPTER_PROXY_H