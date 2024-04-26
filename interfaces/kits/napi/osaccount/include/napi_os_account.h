/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_INTERFACES_KITS_NAPI_OSACCOUNT_INCLUDE_NAPI_OS_ACCOUNT_H
#define OS_ACCOUNT_INTERFACES_KITS_NAPI_OSACCOUNT_INCLUDE_NAPI_OS_ACCOUNT_H

#include <uv.h>
#include <map>
#include <mutex>
#include <vector>
#include "os_account_info.h"
#include "os_account_manager.h"
#include "account_log_wrapper.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_account_common.h"

namespace OHOS {
namespace AccountJsKit {
using namespace OHOS::AccountSA;
struct SubscribeCBInfo;

class SubscriberPtr : public OsAccountSubscriber {
public:
    explicit SubscriberPtr(const OsAccountSubscribeInfo &subscribeInfo);
    ~SubscriberPtr() override;

    void OnAccountsChanged(const int &id) override;
    void OnAccountsSwitch(const int &newId, const int &oldId) override;

    void SetEnv(const napi_env &env);
    void SetCallbackRef(const napi_ref &ref);

private:
    void OnAccountsSubNotify(const int &newId, const int &oldId);
    napi_env env_ = nullptr;
    napi_ref ref_ = nullptr;
};

struct QueryOAByIdAsyncContext : public CommonAsyncContext {
    int id = -1;
    OsAccountInfo osAccountInfos;
};

struct RemoveOAAsyncContext : public CommonAsyncContext {
    int id = 0;
};

struct SetOANameAsyncContext : public CommonAsyncContext {
    int id = 0;
    std::string name;
};

struct SetOAConsAsyncContext : public CommonAsyncContext {
    int id = 0;
    bool enable = false;
    std::vector<std::string> constraints;
};

struct ActivateOAAsyncContext : public CommonAsyncContext {
    int id = -1;
};

struct CreateOAAsyncContext : public CommonAsyncContext {
    OsAccountType type;
    std::string name;
    std::string shortName;
    OsAccountInfo osAccountInfos;
    bool hasShortName = false;
};

struct CreateOAForDomainAsyncContext : public CommonAsyncContext {
    OsAccountType type;
    DomainAccountInfo domainInfo;
    OsAccountInfo osAccountInfos;
    CreateOsAccountForDomainOptions domainOptions;
    ThreadLockInfo *lockInfo;
};

struct GetOACountAsyncContext : public CommonAsyncContext {
    unsigned int osAccountsCount = 0;
};

struct DbDeviceIdAsyncContext : public CommonAsyncContext {
    std::string deviceId;
};

struct GetAllConsAsyncContext : public CommonAsyncContext {
    int id = 0;
    std::vector<std::string> constraints;
};

struct GetIdAsyncContext : public CommonAsyncContext {
    int id = 0;
};

struct QueryCreateOAAsyncContext : public CommonAsyncContext {
    std::vector<OsAccountInfo> osAccountInfos;
};

struct QueryOAConstraintSrcTypeContext : public CommonAsyncContext {
    int32_t id = 0;
    std::string constraint;
    std::vector<ConstraintSourceTypeInfo> constraintSourceTypeInfos;
};

struct QueryActiveIdsAsyncContext : public CommonAsyncContext {
    std::vector<int> osAccountIds;
};

struct GetForegroundOALocalIdAsyncContext : public CommonAsyncContext {
    int id = 0;
};

struct GetOAPhotoAsyncContext : public CommonAsyncContext {
    int id = 0;
    std::string photo;
};

struct GetOsAccountNameContext : public CommonAsyncContext {
    std::string name;
};

struct CurrentOAAsyncContext : public CommonAsyncContext {
    OsAccountInfo osAccountInfos;
};

struct GetIdByUidAsyncContext : public CommonAsyncContext {
    int id = 0;
    int uid = 0;
};

struct GetIdByDomainAsyncContext : public CommonAsyncContext {
    int id = 0;
    DomainAccountInfo domainInfo;
};

struct SetOAPhotoAsyncContext : public CommonAsyncContext {
    int id = 0;
    std::string photo;
};

struct QueryMaxNumAsyncContext : public CommonAsyncContext {
    uint32_t maxOsAccountNumber = 0;
    uint32_t maxLoggedInNumber = 0;
};

struct IsActivedAsyncContext : public CommonAsyncContext {
    int id = -1;
    bool isOsAccountActived = false;
};

struct IsConEnableAsyncContext : public CommonAsyncContext {
    int id = 0;
    std::string constraint;
    bool isConsEnable = false;
};

struct GetTypeAsyncContext : public CommonAsyncContext {
    int id = -1;
    bool withId = false;
    OsAccountType type;
};

struct IsMultiEnAsyncContext : public CommonAsyncContext {
    bool isMultiOAEnable = false;
};

struct IsVerifiedAsyncContext : public CommonAsyncContext {
    int id = -1;
    bool isTestOA = false;
};

struct GetSerialNumIdCBInfo : public CommonAsyncContext {
    int id = 0;
    int64_t serialNumber;
};

struct GetSerialNumForOAInfo : public CommonAsyncContext {
    int id = 0;
    int64_t serialNum;
};

struct IsTestOAInfo : public CommonAsyncContext {
    bool isTestOsAccount = false;
};

struct IsMainOAInfo : public CommonAsyncContext {
    bool isMainOsAccount = false;
};

struct SubscribeCBInfo : public CommonAsyncContext {
    SubscribeCBInfo(napi_env napiEnv) : CommonAsyncContext(napiEnv) {};
    OS_ACCOUNT_SUBSCRIBE_TYPE osSubscribeType = OS_ACCOUNT_SUBSCRIBE_TYPE::INVALID_TYPE;
    std::string name;
    OsAccountManager *osManager = nullptr;
    std::shared_ptr<SubscriberPtr> subscriber = nullptr;
};

struct SubscriberOAWorker : public CommonAsyncContext {
    int oldId = 0;
    int newId = 0;
    napi_ref ref = nullptr;
    SubscriberPtr *subscriber = nullptr;
};

struct UnsubscribeCBInfo : public CommonAsyncContext {
    UnsubscribeCBInfo(napi_env napiEnv) : CommonAsyncContext(napiEnv){};
    OS_ACCOUNT_SUBSCRIBE_TYPE osSubscribeType = OS_ACCOUNT_SUBSCRIBE_TYPE::INVALID_TYPE;
    std::string name;
    OsAccountManager *osManager = nullptr;
    std::vector<std::shared_ptr<SubscriberPtr>> subscribers;
};

napi_value OsAccountInit(napi_env env, napi_value exports);

napi_value GetAccountManager(napi_env env, napi_callback_info cbInfo);

napi_value OsAccountJsConstructor(napi_env env, napi_callback_info cbinfo);

napi_value QueryOsAccountById(napi_env env, napi_callback_info cbInfo);

napi_value RemoveOsAccount(napi_env env, napi_callback_info cbInfo);

napi_value SetOsAccountName(napi_env env, napi_callback_info cbInfo);

napi_value SetOsAccountConstraints(napi_env env, napi_callback_info cbInfo);

napi_value ActivateOsAccount(napi_env env, napi_callback_info cbInfo);

napi_value DeactivateOsAccount(napi_env env, napi_callback_info cbInfo);

napi_value CreateOsAccount(napi_env env, napi_callback_info cbInfo);

napi_value CreateOsAccountForDomain(napi_env env, napi_callback_info cbInfo);

napi_value GetOsAccountCount(napi_env env, napi_callback_info cbInfo);

napi_value GetCreatedOsAccountsCount(napi_env env, napi_callback_info cbInfo);

napi_value GetCreatedOsAccountsCountInner(napi_env env, napi_callback_info cbInfo, bool throwErr);

napi_value QueryDistributedVirtualDeviceId(napi_env env, napi_callback_info cbInfo);

napi_value GetDistributedVirtualDeviceId(napi_env env, napi_callback_info cbInfo);

napi_value GetDistributedVirtualDeviceIdInner(napi_env env, napi_callback_info cbInfo, bool throwErr);

napi_value GetOsAccountConstraints(napi_env env, napi_callback_info cbInfo);

napi_value GetOsAccountAllConstraints(napi_env env, napi_callback_info cbInfo);

napi_value GetOsAccountAllConstraintsInner(napi_env env, napi_callback_info cbInfo, bool throwErr);

napi_value QueryOsAccountLocalIdFromProcess(napi_env env, napi_callback_info cbInfo);

napi_value GetOsAccountLocalIdFromProcess(napi_env env, napi_callback_info cbInfo);

napi_value GetOsAccountLocalIdFromProcessInner(napi_env env, napi_callback_info cbInfo, bool throwErr);

napi_value QueryAllCreatedOsAccounts(napi_env env, napi_callback_info cbInfo);

napi_value GetActivatedOsAccountIds(napi_env env, napi_callback_info cbInfo);

napi_value GetForegroundOsAccountLocalId(napi_env env, napi_callback_info cbInfo);

napi_value QueryActivatedOsAccountIds(napi_env env, napi_callback_info cbInfo);

napi_value QueryActivatedOsAccountIdsInner(napi_env env, napi_callback_info cbInfo, bool throwErr);

napi_value GetOsAccountProfilePhoto(napi_env env, napi_callback_info cbInfo);

napi_value GetOsAccountName(napi_env env, napi_callback_info cbInfo);

napi_value GetCurrentOsAccount(napi_env env, napi_callback_info cbInfo);

napi_value QueryCurrentOsAccount(napi_env env, napi_callback_info cbInfo);

napi_value QueryCurrentOsAccountInner(napi_env env, napi_callback_info cbInfo, bool throwErr);

napi_value GetOsAccountLocalIdFromUid(napi_env env, napi_callback_info cbInfo);

napi_value GetOsAccountLocalIdForUid(napi_env env, napi_callback_info cbInfo);

napi_value GetOsAccountLocalIdForUidSync(napi_env env, napi_callback_info cbInfo);

napi_value GetOsAccountLocalIdFromUidInner(napi_env env, napi_callback_info cbInfo, bool throwErr);

napi_value GetBundleIdFromUid(napi_env env, napi_callback_info cbInfo);

napi_value GetBundleIdForUidSync(napi_env env, napi_callback_info cbInfo);

napi_value GetOsAccountLocalIdFromDomain(napi_env env, napi_callback_info cbInfo);

napi_value QueryOsAccountLocalIdFromDomain(napi_env env, napi_callback_info cbInfo);

napi_value GetOsAccountLocalIdFromDomainInner(napi_env env, napi_callback_info cbInfo, bool throwErr);

napi_value SetOsAccountProfilePhoto(napi_env env, napi_callback_info cbInfo);

napi_value QueryMaxOsAccountNumber(napi_env env, napi_callback_info cbInfo);

napi_value QueryMaxLoggedInOsAccountNumber(napi_env env, napi_callback_info cbInfo);

napi_value QueryOsAccountConstraintSourceTypes(napi_env env, napi_callback_info cbInfo);

napi_value IsOsAccountActived(napi_env env, napi_callback_info cbInfo);

napi_value CheckOsAccountActivated(napi_env env, napi_callback_info cbInfo);

napi_value IsOsAccountConstraintEnable(napi_env env, napi_callback_info cbInfo);

napi_value CheckConstraintEnabled(napi_env env, napi_callback_info cbInfo);

napi_value GetOsAccountType(napi_env env, napi_callback_info cbInfo);

napi_value GetOsAccountTypeFromProcess(napi_env env, napi_callback_info cbInfo);

napi_value GetOsAccountTypeFromProcessInner(napi_env env, napi_callback_info cbInfo, bool throwErr);

napi_value IsMultiOsAccountEnable(napi_env env, napi_callback_info cbInfo);

napi_value CheckMultiOsAccountEnabled(napi_env env, napi_callback_info cbInfo);

napi_value InnerIsMultiOsAccountEnable(napi_env env, napi_callback_info cbInfo, bool throwErr);

napi_value IsOsAccountVerified(napi_env env, napi_callback_info cbInfo);

napi_value CheckOsAccountVerified(napi_env env, napi_callback_info cbInfo);

napi_value GetApplicationConstraints(napi_env env, napi_callback_info cbInfo);

napi_value QueryOsAccountLocalIdBySerialNumber(napi_env env, napi_callback_info cbInfo);

napi_value GetOsAccountLocalIdBySerialNumber(napi_env env, napi_callback_info cbInfo);

napi_value GetOsAccountLocalIdBySerialNumberInner(napi_env env, napi_callback_info cbInfo, bool throwErr);

napi_value QuerySerialNumberByOsAccountLocalId(napi_env env, napi_callback_info cbInfo);

napi_value GetSerialNumberByOsAccountLocalId(napi_env env, napi_callback_info cbInfo);

napi_value GetSerialNumberByOsAccountLocalIdInner(napi_env env, napi_callback_info cbInfo, bool throwErr);

napi_value IsTestOsAccount(napi_env env, napi_callback_info cbInfo);

napi_value CheckOsAccountTestable(napi_env env, napi_callback_info cbInfo);

napi_value InnerIsTestOsAccount(napi_env env, napi_callback_info cbInfo, bool throwErr);

napi_value IsMainOsAccount(napi_env env, napi_callback_info cbInfo);

napi_value Subscribe(napi_env env, napi_callback_info cbInfo);

napi_value Unsubscribe(napi_env env, napi_callback_info cbInfo);

void UvQueueWorkOnAccountsSubNotify(uv_work_t *work, int status);

void UnsubscribeSync(napi_env env, UnsubscribeCBInfo *unsubscribeCBInfo);

void SetEnumProperty(napi_env env, napi_value dstObj, const int objValue, const char *propName);

napi_value IsOsAccountActivated(napi_env env, napi_callback_info cbInfo);

napi_value IsOsAccountConstraintEnabled(napi_env env, napi_callback_info cbInfo);

napi_value IsOsAccountUnlocked(napi_env env, napi_callback_info cbInfo);

napi_value GetEnabledOsAccountConstraints(napi_env env, napi_callback_info cbInfo);

napi_value QueryOsAccount(napi_env env, napi_callback_info cbInfo);
}  // namespace AccountJsKit
}  // namespace OHOS

#endif  // OS_ACCOUNT_INTERFACES_KITS_NAPI_OSACCOUNT_INCLUDE_NAPI_OS_ACCOUNT_H
