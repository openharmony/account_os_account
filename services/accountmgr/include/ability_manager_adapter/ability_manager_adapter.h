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

#ifndef OS_ACCOUNT_SERVICE_ABILITY_MANAGER_ADAPTER_H
#define OS_ACCOUNT_SERVICE_ABILITY_MANAGER_ADAPTER_H

#include <mutex>

#include "ability_connect_callback_interface.h"
#include "stop_user_callback.h"
#include "want.h"

namespace OHOS {
namespace AccountSA {
using namespace AAFwk;
/**
 * @class AbilityManagerAdapter
 * AbilityManagerAdapter is used to access ability manager services.
 */
class AbilityManagerAdapter {
public:
    AbilityManagerAdapter();
    virtual ~AbilityManagerAdapter();
    static std::shared_ptr<AbilityManagerAdapter> GetInstance();

    /**
     * ConnectAbility, connect session with service ability.
     *
     * @param want, Special want for service type's ability.
     * @param connect, Callback used to notify caller the result of connecting or disconnecting.
     * @param callerToken, caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode ConnectAbility(
        const Want &want,
        const sptr<IAbilityConnection> &connect,
        const sptr<IRemoteObject> &callerToken,
        int32_t userId = -1);

    /**
     * DisconnectAbility, disconnect session with service ability.
     *
     * @param connect, Callback used to notify caller the result of connecting or disconnecting.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode DisconnectAbility(const sptr<IAbilityConnection> &connect);

    /**
     * @brief start user.
     * @param accountId accountId.
     *
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode StartUser(int32_t accountId);

    /**
     * @brief stop user.
     * @param accountId accountId.
     * @param callback callback.
     *
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode StopUser(int32_t accountId, const sptr<IStopUserCallback> &callback);

private:
    void Connect();
    ErrCode DoConnectAbility(
        const sptr<IRemoteObject> proxy,
        const Want &want,
        const sptr<IAbilityConnection> &connect,
        const sptr<IRemoteObject> &callerToken,
        int32_t userId = -1);

    class AbilityMgrDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        AbilityMgrDeathRecipient() = default;
        ~AbilityMgrDeathRecipient() = default;
        void OnRemoteDied(const wptr<IRemoteObject>& remote) override;
    private:
        DISALLOW_COPY_AND_MOVE(AbilityMgrDeathRecipient);
    };

    sptr<IRemoteObject> GetAbilityManager();
    void ResetProxy(const wptr<IRemoteObject>& remote);

    static std::mutex instanceMutex_;
    static std::shared_ptr<AbilityManagerAdapter> instance_;
    std::mutex proxyMutex_;
    sptr<IRemoteObject> proxy_;
    sptr<IRemoteObject::DeathRecipient> deathRecipient_;
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OS_ACCOUNT_SERVICE_ABILITY_MANAGER_ADAPTER_H
