/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OHOS_ACCOUNT_MANAGER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OHOS_ACCOUNT_MANAGER_H

#include <map>
#include <mutex>
#include <set>
#include <string>
#ifdef HAS_CES_PART
#include "account_event_subscribe.h"
#endif // HAS_CES_PART
#include "account_info.h"
#include "account_state_machine.h"
#include "idistributed_account_subscribe.h"
#include "iinner_os_account_manager.h"
#include "ohos_account_data_deal.h"

namespace OHOS {
namespace AccountSA {
#ifndef ACCOUNT_TEST
const std::string ACCOUNT_CFG_DIR_ROOT_PATH = "/data/service/el1/public/account/";
#else
const std::string ACCOUNT_CFG_DIR_ROOT_PATH = "/data/service/el1/public/account/test/";
#endif // ACCOUNT_TEST


class OhosAccountManager;
#ifndef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
using OhosAccountEventFunc = std::function<ErrCode(const std::int32_t, const OhosAccountInfo &, const std::string &)>;
#else
using OhosAccountEventFunc =
    std::function<ErrCode(const std::int32_t, const std::int32_t, const OhosAccountInfo &, const std::string &)>;
#endif
/**
 * Ohos account manager
 */
class OhosAccountManager {
public:
    static OhosAccountManager &GetInstance();
    /**
     * Get current ohos account information.
     *
     * @return current account information.
     */
    AccountInfo GetCurrentOhosAccountInfo();

    /**
     * Get ohos account information by local userId.
     * @param userId target local account id
     * @return ohos account info which is bound to the local userId.
     */
    ErrCode GetOhosAccountDistributedInfo(const int32_t userId, OhosAccountInfo &ohosAccountInfo);

    /**
     * Get ohos account information by local userId.
     *
     * @param userId target local account id
     * @return ohos account info which is bound to the local userId.
     */
    ErrCode GetAccountInfoByUserId(std::int32_t userId, AccountInfo &info);

    /**
     * Get ohos account device id.
     *
     * @return ohos account device id.
     */
    ErrCode QueryDistributedVirtualDeviceId(std::string &dvid);

    /**
     * Get ohos account device id.
     *
     * @param bundleName target bundle name
     * @param localId target local account id
     * @return dvid ohos account device id.
     */
    ErrCode QueryDistributedVirtualDeviceId(const std::string &bundleName, int32_t localId, std::string &dvid);

    /**
     * Subscribe distributed account event by type.
     *
     * @param type event type
     * @param eventListener event listener
     * @return subscribe resule.
     */
    ErrCode SubscribeDistributedAccountEvent(const DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type,
        const sptr<IRemoteObject> &eventListener);

    /**
     * Unsubscribe distributed account event by type.
     *
     * @param type event type
     * @param eventListener event listener
     * @return unsubscribe resule.
     */
    ErrCode UnsubscribeDistributedAccountEvent(const DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type,
        const sptr<IRemoteObject> &eventListener);

#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
    void InitOsAccountSubspaceManager(const std::string &rootPath);
    ErrCode CreateOsAccountSubspace(int32_t osAccountId, OsAccountSubspaceResult &result);
    ErrCode DeleteOsAccountSubspace(int32_t osAccountId, int32_t subspaceId);
    ErrCode SwitchOsAccountSubspace(int32_t osAccountId, int32_t subspaceId, int32_t &fromSubspaceId);
#endif  // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE

    /**
     * Subscribe distributed account space events by multiple types.
     *
     * @param types space event types set
     * @param eventListener event listener
     * @return subscribe result.
     */
    ErrCode SubscribeDistributedAccountSpaceEvents(const std::set<DistributedAccountSpaceEventType> &types,
        const sptr<IRemoteObject> &eventListener);

    /**
     * Unsubscribe distributed account space events by multiple types.
     *
     * @param types space event types set
     * @param eventListener event listener
     * @return unsubscribe result.
     */
    ErrCode UnsubscribeDistributedAccountSpaceEvents(const std::set<DistributedAccountSpaceEventType> &types,
        const sptr<IRemoteObject> &eventListener);

    /**
     * Get current account state.
     *
     * @return current account state id.
     */
    int GetCurrentOhosAccountState();

    /**
     * Init ohos account manager.
     *
     */
    bool OnInitialize();

    /**
     * Process an account event.
     *
     * @param curOhosAccount current ohos account info
     * @param eventStr ohos account state change event
     * @return true if the processing was completed, otherwise false
     */
    bool HandleEvent(AccountInfo &curOhosAccount, const std::string &eventStr);

    ErrCode SendLogoutEventOnDelOsAccount(int32_t localId);

#ifndef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
    /**
     * login ohos (for distributed network) account.
     *
     * @param userId target local account id.
     * @param ohosAccountInfo ohos account information
     * @param eventStr ohos account state change event
     * @return true if the processing was completed, otherwise false
     */
    ErrCode LoginOhosAccount(const int32_t userId,
        const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr);

    /**
     * logout ohos (for distributed network) account.
     *
     * @param userId target local account id.
     * @param ohosAccountInfo ohos account information
     * @param eventStr ohos account state change event
     * @return true if the processing was completed, otherwise false
     */
    ErrCode LogoutOhosAccount(const int32_t userId, const OhosAccountInfo &ohosAccountInfo,
                              const std::string &eventStr);

    /**
     * logoff ohos (for distributed network) account.
     *
     * @param userId target local account id.
     * @param ohosAccountInfo ohos account information
     * @param eventStr ohos account state change event
     * @return true if the processing was completed, otherwise false
     */
    ErrCode LogoffOhosAccount(const int32_t userId, const OhosAccountInfo &ohosAccountInfo,
                              const std::string &eventStr);

    /**
     * Handle token_invalid event of ohos (for distributed network) account .
     *
     * @param userId target local account id.
     * @param ohosAccountInfo ohos account information
     * @param eventStr ohos account state change event
     * @return true if the processing was completed, otherwise false
     */
    ErrCode HandleOhosAccountTokenInvalidEvent(
        const int32_t userId, const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr);
#else
    ErrCode LoginOhosAccountSpace(int32_t userId, int32_t subspaceId,
        const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr);
    ErrCode LogoutOhosAccountSpace(int32_t userId, int32_t subspaceId,
        const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr);
    ErrCode HandleOhosAccountSpaceTokenInvalidEvent(int32_t userId, int32_t subspaceId,
        const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr);
    ErrCode LogoffOhosAccountSpace(int32_t userId, int32_t subspaceId,
        const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr);
    ErrCode HandleSpaceStateChange(OsAccountSubspaceInfo &spaceInfo, const std::string &eventStr);
#endif // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
    /**
     * Ohos account state change.
     *
     * @param name ohos account name
     * @param uid ohos account uid
     * @param eventStr ohos account state change event
     * @return true if the processing was completed, otherwise false
     */
    ErrCode OhosAccountStateChange(const std::string &name, const std::string &uid, const std::string &eventStr);

    /**
     * Ohos account state change.
     *
     * @param ohosAccountInfo ohos account information
     * @param eventStr ohos account state change event
     * @return true if the processing was completed, otherwise false
     */
    ErrCode OhosAccountStateChange(
        const int32_t userId, const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr);

private:
    bool isInit_ = false;
    OhosAccountManager();
    DISALLOW_COPY_AND_MOVE(OhosAccountManager);
    IDistributedAccountSubscribe &subscribeManager_;

    /**
     * Account state machine.
     */
    std::unique_ptr<AccountStateMachine> accountState_{};

    /**
     * Deal with file storage.
     */
    std::unique_ptr<OhosAccountDataDeal> dataDealer_{};

    /**
     * mutex lock for synchronization.
     */
    std::mutex mgrMutex_;
    std::mutex initMutex_;

    /**
     * Config current account config.
     *
     * @param ohosAccountInfo target ohos account information.
     * @return true if success.
     */
    bool SaveOhosAccountInfo(AccountInfo &ohosAccountInfo) const;

    /**
     * Clear current account config.
     * @param curOhosAccountInfo current ohos account info.
     * @param clrStatus account status.
     */
    bool ClearOhosAccount(AccountInfo &curOhosAccountInfo, std::int32_t clrStatus = ACCOUNT_STATE_UNBOUND) const;

    /**
     * Check whether the ohos account can be bound to the current user or not
     * @return true if can.
     */
    bool CheckOhosAccountCanBind(const AccountInfo &currAccountInfo,
        const OhosAccountInfo &newOhosAccountInfo, const std::string &newOhosUid) const;

    /**
     * Get current ohos account info and check whether input information match or not
     * @return true if matches.
     */
    bool GetCurOhosAccountAndCheckMatch(AccountInfo &curOhosAccountInfo,
                                        const std::string &inputName,
                                        const std::string &inputUid,
                                        const std::int32_t callingUserId) const;
    bool CheckSameDistributedAccount(const OhosAccountInfo &currAccountInfo, const OhosAccountInfo &newOhosAccountInfo,
        const std::int32_t callingUserId) const;

    std::string ExtractFirstUtf8Char(const std::string &str);
    void AnonymizeOhosAccountInfo(OhosAccountInfo &ohosAccountInfo, const std::string &bundleName);

#ifdef HAS_CES_PART
    void OnPackageRemoved(const std::int32_t callingUid);
    bool CreateCommonEventSubscribe();
    void ClearMainAccountIfMatch(int32_t localId, const std::int32_t bundleUid);
#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
    void ClearDistributedAccountSpacesIfMatch(int32_t localId, const std::int32_t bundleUid);
    void ClearDistributedAccountSpaceIfMatch(int32_t localId, int32_t spaceId, const std::int32_t callingUid);
#endif // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
    std::shared_ptr<AccountEventSubscriber> accountEventSubscribe_{};
#endif // HAS_CES_PART
#ifndef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
    ErrCode PublishLoginEvents(int32_t userId, int32_t originalStatus);
#else
    ErrCode VerifySpaceAccountBinding(int32_t userId, int32_t subspaceId,
        const OhosAccountInfo &accountInfo, const OsAccountSubspaceInfo &spaceInfo);
    ErrCode PublishLoginSpaceEvents(int32_t userId, int32_t subspaceId,
        const OsAccountSubspaceInfo &spaceInfo, bool isUnbound);
    void PublishLogoutSpaceEvents(int32_t localId, int32_t subspaceId, bool isUnbound);
    ErrCode GetDistributedAccountSpaceInfo(int32_t userId, int32_t subspaceId, OsAccountSubspaceInfo &spaceInfo);
    ErrCode SetDistributedAccountSpaceInfo(const OsAccountSubspaceInfo &spaceInfo);
    ErrCode SendMultiSpaceLogoutOnDelOsAccount(int32_t localId);
#endif
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OHOS_ACCOUNT_MANAGER_H
