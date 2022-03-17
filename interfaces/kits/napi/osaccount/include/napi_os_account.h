/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef NAPI_OS_ACCOUNT_H
#define NAPI_OS_ACCOUNT_H

#include <uv.h>
#include <map>
#include <mutex>
#include <vector>
#include "os_account_info.h"
#include "os_account_manager.h"
#include "account_log_wrapper.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace AccountJsKit {
using namespace OHOS::AccountSA;
struct SubscribeCBInfo;

const std::string OS_ACCOUNT_CLASS_NAME = "AccountManager";
static thread_local napi_ref osAccountRef_ = nullptr;

class SubscriberPtr : public OsAccountSubscriber {
public:
    SubscriberPtr(const OsAccountSubscribeInfo &subscribeInfo);
    ~SubscriberPtr();

    virtual void OnAccountsChanged(const int &id) override;

    void SetEnv(const napi_env &env);
    void SetCallbackRef(const napi_ref &ref);

private:
    napi_env env_ = nullptr;
    napi_ref ref_ = nullptr;
};

struct QueryOAByIdAsyncContext {
    napi_env env;
    napi_async_work work;

    int id = -1;
    int errCode = 0;
    OsAccountInfo osAccountInfos;

    napi_deferred deferred;
    napi_ref callbackRef;
    napi_status status;
};

struct RemoveOAAsyncContext {
    napi_env env;
    napi_async_work work;

    int id = 0;
    int errCode = 0;

    napi_deferred deferred;
    napi_ref callbackRef;
    napi_status status;
};

struct SetOANameAsyncContext {
    napi_env env;
    napi_async_work work;

    int id = 0;
    int errCode = 0;
    std::string name;

    napi_deferred deferred;
    napi_ref callbackRef;
    napi_status status;
};

struct SetOAConsAsyncContext {
    napi_env env;
    napi_async_work work;

    int id = 0;
    int errCode = 0;
    bool enable = false;
    std::vector<std::string> constraints;

    napi_deferred deferred;
    napi_ref callbackRef;
    napi_status status;
};

struct ActivateOAAsyncContext {
    napi_env env;
    napi_async_work work;

    int id = -1;
    int errCode = 0;

    napi_deferred deferred;
    napi_ref callbackRef;
    napi_status status;
};

struct CreateOAAsyncContext {
    napi_env env;
    napi_async_work work;

    OsAccountType type;
    int errCode = 0;
    std::string name;
    OsAccountInfo osAccountInfos;

    napi_deferred deferred;
    napi_ref callbackRef;
    napi_status status;
};

struct CreateOAForDomainAsyncContext {
    napi_env env;
    napi_async_work work;

    OsAccountType type;
    int errCode = 0;
    DomainAccountInfo domainInfo;
    OsAccountInfo osAccountInfos;

    napi_deferred deferred;
    napi_ref callbackRef;
    napi_status status;
};

struct GetOACountAsyncContext {
    napi_env env;
    napi_async_work work;

    unsigned int osAccountsCount = 0;
    int errCode = 0;

    napi_deferred deferred;
    napi_ref callbackRef;
    napi_status status;
};

struct DbDeviceIdAsyncContext {
    napi_env env;
    napi_async_work work;

    std::string deviceId;
    int errCode = 0;

    napi_deferred deferred;
    napi_ref callbackRef;
    napi_status status;
};

struct GetAllConsAsyncContext {
    napi_env env;
    napi_async_work work;

    int id = 0;
    int errCode = 0;
    std::vector<std::string> constraints;

    napi_deferred deferred;
    napi_ref callbackRef;
    napi_status status;
};

struct GetIdAsyncContext {
    napi_env env;
    napi_async_work work;

    int id = 0;
    int errCode = 0;

    napi_deferred deferred;
    napi_ref callbackRef;
    napi_status status;
};

struct QueryCreateOAAsyncContext {
    napi_env env;
    napi_async_work work;

    int errCode = 0;
    std::vector<OsAccountInfo> osAccountInfos;

    napi_deferred deferred;
    napi_ref callbackRef;
    napi_status status;
};

struct QueryActiveIdsAsyncContext {
    napi_env env;
    napi_async_work work;

    int errCode = 0;
    std::vector<int> osAccountIds;

    napi_deferred deferred;
    napi_ref callbackRef;
    napi_status status;
};

struct GetOAPhotoAsyncContext {
    napi_env env;
    napi_async_work work;

    int id = 0;
    int errCode = 0;
    std::string photo;

    napi_deferred deferred;
    napi_ref callbackRef;
    napi_status status;
};

struct CurrentOAAsyncContext {
    napi_env env;
    napi_async_work work;

    int errCode = 0;
    OsAccountInfo osAccountInfos;

    napi_deferred deferred;
    napi_ref callbackRef;
    napi_status status;
};

struct GetIdByUidAsyncContext {
    napi_env env;
    napi_async_work work;

    int id = 0;
    int uid = 0;
    int errCode = 0;

    napi_deferred deferred;
    napi_ref callbackRef;
    napi_status status;
};

struct GetIdByDomainAsyncContext {
    napi_env env;
    napi_async_work work;

    int id = 0;
    DomainAccountInfo domainInfo;
    int errCode = 0;

    napi_deferred deferred;
    napi_ref callbackRef;
    napi_status status;
};

struct SetOAPhotoAsyncContext {
    napi_env env;
    napi_async_work work;

    int id = 0;
    int errCode = 0;
    std::string photo;

    napi_deferred deferred;
    napi_ref callbackRef;
    napi_status status;
};

struct QueryMaxNumAsyncContext {
    napi_env env;
    napi_async_work work;

    int maxOsAccountNumber = 0;
    int errCode = 0;

    napi_deferred deferred;
    napi_ref callbackRef;
    napi_status status;
};

struct IsActivedAsyncContext {
    napi_env env;
    napi_async_work work;

    int id = -1;
    int errCode = 0;
    bool isOsAccountActived = false;

    napi_deferred deferred;
    napi_ref callbackRef;
    napi_status status;
};

struct IsConEnableAsyncContext {
    napi_env env;
    napi_async_work work;

    int id = 0;
    int errCode = 0;
    std::string constraint;
    bool isConsEnable = false;

    napi_deferred deferred;
    napi_ref callbackRef;
    napi_status status;
};

struct GetTypeAsyncContext {
    napi_env env;
    napi_async_work work;

    OsAccountType type;
    int errCode = 0;

    napi_deferred deferred;
    napi_ref callbackRef;
    napi_status status;
};

struct IsMultiEnAsyncContext {
    napi_env env;
    napi_async_work work;

    int errCode = 0;
    bool isMultiOAEnable = false;

    napi_deferred deferred;
    napi_ref callbackRef;
    napi_status status;
};

struct IsVerifiedAsyncContext {
    napi_env env;
    napi_async_work work;

    int id = 0;
    int errCode = 0;
    bool isTestOA = false;

    napi_deferred deferred;
    napi_ref callbackRef;
    napi_status status;
};

struct GetSerialNumIdCBInfo {
    napi_env env;
    napi_async_work work;

    int id = 0;
    int errCode = 0;
    int64_t serialNumber;

    napi_deferred deferred;
    napi_ref callbackRef;
    napi_status status;
};

struct GetSerialNumForOAInfo {
    napi_env env;
    napi_async_work work;

    int id = 0;
    int errCode = 0;
    int64_t serialNum;

    napi_deferred deferred;
    napi_ref callbackRef;
    napi_status status;
};

struct IsTestOAInfo {
    napi_env env;
    napi_async_work work;

    int errCode = 0;
    bool isTestOsAccount = false;

    napi_deferred deferred;
    napi_ref callbackRef;
    napi_status status;
};

struct SubscribeCBInfo {
    napi_env env;
    napi_async_work work;
    napi_ref callbackRef;
    OS_ACCOUNT_SUBSCRIBE_TYPE osSubscribeType;
    std::string name;
    OsAccountManager *osManager = nullptr;
    std::shared_ptr<SubscriberPtr> subscriber = nullptr;
};

struct SubscriberOAWorker {
    int id = 0;
    napi_env env = nullptr;
    napi_ref ref = nullptr;
    SubscriberPtr *subscriber = nullptr;
};

struct UnsubscribeCBInfo {
    napi_env env;
    napi_async_work work;
    napi_ref callbackRef;
    size_t argc = 0;
    OS_ACCOUNT_SUBSCRIBE_TYPE osSubscribeType;
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

napi_value CreateOsAccount(napi_env env, napi_callback_info cbInfo);

napi_value CreateOsAccountForDomain(napi_env env, napi_callback_info cbInfo);

napi_value GetCreatedOsAccountsCount(napi_env env, napi_callback_info cbInfo);

napi_value GetDistributedVirtualDeviceId(napi_env env, napi_callback_info cbInfo);

napi_value GetOsAccountAllConstraints(napi_env env, napi_callback_info cbInfo);

napi_value GetOsAccountLocalIdFromProcess(napi_env env, napi_callback_info cbInfo);

napi_value QueryAllCreatedOsAccounts(napi_env env, napi_callback_info cbInfo);

napi_value QueryActivatedOsAccountIds(napi_env env, napi_callback_info cbInfo);

napi_value GetOsAccountProfilePhoto(napi_env env, napi_callback_info cbInfo);

napi_value QueryCurrentOsAccount(napi_env env, napi_callback_info cbInfo);

napi_value GetOsAccountLocalIdFromUid(napi_env env, napi_callback_info cbInfo);

napi_value GetOsAccountLocalIdFromDomain(napi_env env, napi_callback_info cbInfo);

napi_value SetOsAccountProfilePhoto(napi_env env, napi_callback_info cbInfo);

napi_value QueryMaxOsAccountNumber(napi_env env, napi_callback_info cbInfo);

napi_value IsOsAccountActived(napi_env env, napi_callback_info cbInfo);

napi_value IsOsAccountConstraintEnable(napi_env env, napi_callback_info cbInfo);

napi_value GetOsAccountTypeFromProcess(napi_env env, napi_callback_info cbInfo);

napi_value IsMultiOsAccountEnable(napi_env env, napi_callback_info cbInfo);

napi_value IsOsAccountVerified(napi_env env, napi_callback_info cbInfo);

napi_value GetApplicationConstraints(napi_env env, napi_callback_info cbInfo);

napi_value GetOsAccountLocalIdBySerialNumber(napi_env env, napi_callback_info cbInfo);

napi_value GetSerialNumberByOsAccountLocalId(napi_env env, napi_callback_info cbInfo);

napi_value IsTestOsAccount(napi_env env, napi_callback_info cbInfo);

napi_value Subscribe(napi_env env, napi_callback_info cbInfo);

napi_value Unsubscribe(napi_env env, napi_callback_info cbInfo);

void UvQueueWorkOnAccountsChanged(uv_work_t *work, int status);

void FindSubscriberInMap(
    std::vector<std::shared_ptr<SubscriberPtr>> &subscribers, UnsubscribeCBInfo *unsubscribeCBInfo, bool &isFind);

void UnsubscribeExecuteCB(napi_env env, void *data);

void UnsubscribeCallbackCompletedCB(napi_env env, napi_status status, void *data);

void SetEnumProperty(napi_env env, napi_value dstObj, const int objValue, const char *propName);
}  // namespace AccountJsKit
}  // namespace OHOS
#endif  // NAPI_OS_ACCOUNT_H
