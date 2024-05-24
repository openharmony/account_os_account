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

#include "napi_os_account.h"
#include "account_permission_manager.h"
#include "napi_account_error.h"
#include "napi_os_account_common.h"
#include "napi/native_common.h"

using namespace OHOS::AccountSA;

namespace OHOS {
namespace AccountJsKit {
namespace {
const std::string OS_ACCOUNT_CLASS_NAME = "AccountManager";
static thread_local napi_ref osAccountRef_ = nullptr;

const int OS_ACCOUNT_TYPE_ADMIN = 0;
const int OS_ACCOUNT_TYPE_NORMAL = 1;
const int OS_ACCOUNT_TYPE_GUEST = 2;
const int OS_ACCOUNT_TYPE_PRIVATE = 1024;
const int DOMAIN_ACCOUNT_STATUS_NOT_LOGGED_IN = 0;
const int DOMAIN_ACCOUNT_STATUS_LOGGED_IN = 1;
std::mutex g_lockForOsAccountSubscribers;
std::map<OsAccountManager *, std::vector<SubscribeCBInfo *>> g_osAccountSubscribers;
static napi_property_descriptor g_osAccountProperties[] = {
    DECLARE_NAPI_FUNCTION("queryOsAccountById", QueryOsAccountById),
    DECLARE_NAPI_FUNCTION("removeOsAccount", RemoveOsAccount),
    DECLARE_NAPI_FUNCTION("setOsAccountName", SetOsAccountName),
    DECLARE_NAPI_FUNCTION("setOsAccountConstraints", SetOsAccountConstraints),
    DECLARE_NAPI_FUNCTION("activateOsAccount", ActivateOsAccount),
    DECLARE_NAPI_FUNCTION("deactivateOsAccount", DeactivateOsAccount),
    DECLARE_NAPI_FUNCTION("createOsAccount", CreateOsAccount),
    DECLARE_NAPI_FUNCTION("createOsAccountForDomain", CreateOsAccountForDomain),
    DECLARE_NAPI_FUNCTION("getCreatedOsAccountsCount", GetCreatedOsAccountsCount),
    DECLARE_NAPI_FUNCTION("getOsAccountCount", GetOsAccountCount),
    DECLARE_NAPI_FUNCTION("getDistributedVirtualDeviceId", GetDistributedVirtualDeviceId),
    DECLARE_NAPI_FUNCTION("queryDistributedVirtualDeviceId", QueryDistributedVirtualDeviceId),
    DECLARE_NAPI_FUNCTION("getOsAccountAllConstraints", GetOsAccountAllConstraints),
    DECLARE_NAPI_FUNCTION("getOsAccountConstraints", GetOsAccountConstraints),
    DECLARE_NAPI_FUNCTION("getOsAccountLocalIdFromProcess", GetOsAccountLocalIdFromProcess),
    DECLARE_NAPI_FUNCTION("queryOsAccountLocalIdFromProcess", QueryOsAccountLocalIdFromProcess),
    DECLARE_NAPI_FUNCTION("getOsAccountLocalId", QueryOsAccountLocalIdFromProcess),
    DECLARE_NAPI_FUNCTION("queryAllCreatedOsAccounts", QueryAllCreatedOsAccounts),
    DECLARE_NAPI_FUNCTION("queryOsAccountConstraintSourceTypes", QueryOsAccountConstraintSourceTypes),
    DECLARE_NAPI_FUNCTION("getOsAccountConstraintSourceTypes", QueryOsAccountConstraintSourceTypes),
    DECLARE_NAPI_FUNCTION("queryActivatedOsAccountIds", QueryActivatedOsAccountIds),
    DECLARE_NAPI_FUNCTION("getActivatedOsAccountIds", GetActivatedOsAccountIds),
    DECLARE_NAPI_FUNCTION("getActivatedOsAccountLocalIds", GetActivatedOsAccountIds),
    DECLARE_NAPI_FUNCTION("getForegroundOsAccountLocalId", GetForegroundOsAccountLocalId),
    DECLARE_NAPI_FUNCTION("getOsAccountProfilePhoto", GetOsAccountProfilePhoto),
    DECLARE_NAPI_FUNCTION("getOsAccountName", GetOsAccountName),
    DECLARE_NAPI_FUNCTION("queryCurrentOsAccount", QueryCurrentOsAccount),
    DECLARE_NAPI_FUNCTION("getCurrentOsAccount", GetCurrentOsAccount),
    DECLARE_NAPI_FUNCTION("getOsAccountLocalIdFromUid", GetOsAccountLocalIdFromUid),
    DECLARE_NAPI_FUNCTION("getOsAccountLocalIdForUid", GetOsAccountLocalIdForUid),
    DECLARE_NAPI_FUNCTION("getOsAccountLocalIdForUidSync", GetOsAccountLocalIdForUidSync),
    DECLARE_NAPI_FUNCTION("getBundleIdFromUid", GetBundleIdFromUid),
    DECLARE_NAPI_FUNCTION("getBundleIdForUid", GetBundleIdFromUid),
    DECLARE_NAPI_FUNCTION("getBundleIdForUidSync", GetBundleIdForUidSync),
    DECLARE_NAPI_FUNCTION("getOsAccountLocalIdFromDomain", GetOsAccountLocalIdFromDomain),
    DECLARE_NAPI_FUNCTION("queryOsAccountLocalIdFromDomain", QueryOsAccountLocalIdFromDomain),
    DECLARE_NAPI_FUNCTION("getOsAccountLocalIdForDomain", QueryOsAccountLocalIdFromDomain),
    DECLARE_NAPI_FUNCTION("setOsAccountProfilePhoto", SetOsAccountProfilePhoto),
    DECLARE_NAPI_FUNCTION("queryMaxOsAccountNumber", QueryMaxOsAccountNumber),
    DECLARE_NAPI_FUNCTION("queryMaxLoggedInOsAccountNumber", QueryMaxLoggedInOsAccountNumber),
    DECLARE_NAPI_FUNCTION("isOsAccountActived", IsOsAccountActived),
    DECLARE_NAPI_FUNCTION("checkOsAccountActivated", CheckOsAccountActivated),
    DECLARE_NAPI_FUNCTION("isOsAccountConstraintEnable", IsOsAccountConstraintEnable),
    DECLARE_NAPI_FUNCTION("checkConstraintEnabled", CheckConstraintEnabled),
    DECLARE_NAPI_FUNCTION("checkOsAccountConstraintEnabled", CheckConstraintEnabled),
    DECLARE_NAPI_FUNCTION("getOsAccountTypeFromProcess", GetOsAccountTypeFromProcess),
    DECLARE_NAPI_FUNCTION("getOsAccountType", GetOsAccountType),
    DECLARE_NAPI_FUNCTION("isMultiOsAccountEnable", IsMultiOsAccountEnable),
    DECLARE_NAPI_FUNCTION("checkMultiOsAccountEnabled", CheckMultiOsAccountEnabled),
    DECLARE_NAPI_FUNCTION("isOsAccountVerified", IsOsAccountVerified),
    DECLARE_NAPI_FUNCTION("checkOsAccountVerified", CheckOsAccountVerified),
    DECLARE_NAPI_FUNCTION("getOsAccountLocalIdBySerialNumber", GetOsAccountLocalIdBySerialNumber),
    DECLARE_NAPI_FUNCTION("queryOsAccountLocalIdBySerialNumber", QueryOsAccountLocalIdBySerialNumber),
    DECLARE_NAPI_FUNCTION("getOsAccountLocalIdForSerialNumber", QueryOsAccountLocalIdBySerialNumber),
    DECLARE_NAPI_FUNCTION("getSerialNumberByOsAccountLocalId", GetSerialNumberByOsAccountLocalId),
    DECLARE_NAPI_FUNCTION("querySerialNumberByOsAccountLocalId", QuerySerialNumberByOsAccountLocalId),
    DECLARE_NAPI_FUNCTION("getSerialNumberForOsAccountLocalId", QuerySerialNumberByOsAccountLocalId),
    DECLARE_NAPI_FUNCTION("isTestOsAccount", IsTestOsAccount),
    DECLARE_NAPI_FUNCTION("checkOsAccountTestable", CheckOsAccountTestable),
    DECLARE_NAPI_FUNCTION("isMainOsAccount", IsMainOsAccount),
    DECLARE_NAPI_FUNCTION("on", Subscribe),
    DECLARE_NAPI_FUNCTION("off", Unsubscribe),
    DECLARE_NAPI_FUNCTION("isOsAccountActivated", IsOsAccountActivated),
    DECLARE_NAPI_FUNCTION("isOsAccountConstraintEnabled", IsOsAccountConstraintEnabled),
    DECLARE_NAPI_FUNCTION("isOsAccountUnlocked", IsOsAccountUnlocked),
    DECLARE_NAPI_FUNCTION("getEnabledOsAccountConstraints", GetEnabledOsAccountConstraints),
    DECLARE_NAPI_FUNCTION("queryOsAccount", QueryOsAccount),
};
}  // namespace
napi_value OsAccountInit(napi_env env, napi_value exports)
{
    napi_property_descriptor descriptor[] = {
        DECLARE_NAPI_FUNCTION("getAccountManager", GetAccountManager),
    };
    NAPI_CALL(
        env, napi_define_properties(env, exports, sizeof(descriptor) / sizeof(napi_property_descriptor), descriptor));

    napi_value osAccountType = nullptr;
    napi_create_object(env, &osAccountType);

    SetEnumProperty(env, osAccountType, OS_ACCOUNT_TYPE_ADMIN, "ADMIN");
    SetEnumProperty(env, osAccountType, OS_ACCOUNT_TYPE_NORMAL, "NORMAL");
    SetEnumProperty(env, osAccountType, OS_ACCOUNT_TYPE_GUEST, "GUEST");
    SetEnumProperty(env, osAccountType, OS_ACCOUNT_TYPE_PRIVATE, "PRIVATE");

    napi_value constraintSourceType = nullptr;
    napi_create_object(env, &constraintSourceType);
    SetEnumProperty(env, constraintSourceType, CONSTRAINT_NOT_EXIST, "CONSTRAINT_NOT_EXIST");
    SetEnumProperty(env, constraintSourceType, CONSTRAINT_TYPE_BASE, "CONSTRAINT_TYPE_BASE");
    SetEnumProperty(env, constraintSourceType, CONSTRAINT_TYPE_DEVICE_OWNER, "CONSTRAINT_TYPE_DEVICE_OWNER");
    SetEnumProperty(env, constraintSourceType, CONSTRAINT_TYPE_PROFILE_OWNER, "CONSTRAINT_TYPE_PROFILE_OWNER");

    napi_value domainAccountStatus = nullptr;
    napi_create_object(env, &domainAccountStatus);

    SetEnumProperty(env, domainAccountStatus, DOMAIN_ACCOUNT_STATUS_NOT_LOGGED_IN, "NOT_LOGGED_IN");
    SetEnumProperty(env, domainAccountStatus, DOMAIN_ACCOUNT_STATUS_LOGGED_IN, "LOGGED_IN");

    napi_property_descriptor exportEnum[] = {
        DECLARE_NAPI_PROPERTY("OsAccountType", osAccountType),
        DECLARE_NAPI_PROPERTY("ConstraintSourceType", constraintSourceType),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(exportEnum) / sizeof(*exportEnum), exportEnum));
    napi_value cons = nullptr;
    NAPI_CALL(env,
        napi_define_class(env,
            OS_ACCOUNT_CLASS_NAME.c_str(),
            OS_ACCOUNT_CLASS_NAME.size(),
            OsAccountJsConstructor,
            nullptr,
            sizeof(g_osAccountProperties) / sizeof(napi_property_descriptor),
            g_osAccountProperties,
            &cons));
    NAPI_CALL(env, napi_create_reference(env, cons, 1, &osAccountRef_));
    NAPI_CALL(env, napi_set_named_property(env, exports, OS_ACCOUNT_CLASS_NAME.c_str(), cons));

    return exports;
}

napi_value GetAccountManager(napi_env env, napi_callback_info cbInfo)
{
    napi_value instance = nullptr;
    napi_value cons = nullptr;
    if (napi_get_reference_value(env, osAccountRef_, &cons) != napi_ok) {
        return nullptr;
    }

    if (napi_new_instance(env, cons, 0, nullptr, &instance) != napi_ok) {
        return nullptr;
    }

    OsAccountManager *objectInfo = new (std::nothrow) OsAccountManager();
    if (objectInfo == nullptr) {
        ACCOUNT_LOGE("failed to create OsAccountManager for insufficient memory");
        return nullptr;
    }
    napi_status status = napi_wrap(env, instance, objectInfo,
        [](napi_env env, void *data, void *hint) {
            ACCOUNT_LOGI("js OsAccountManager instance garbage collection");
            delete reinterpret_cast<OsAccountManager *>(data);
        }, nullptr, nullptr);
    if (status != napi_ok) {
        ACCOUNT_LOGE("failed to wrap js instance with native object");
        delete objectInfo;
        return nullptr;
    }
    return instance;
}

napi_value OsAccountJsConstructor(napi_env env, napi_callback_info cbinfo)
{
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, nullptr));
    return thisVar;
}

void SetEnumProperty(napi_env env, napi_value dstObj, const int objValue, const char *propName)
{
    napi_value prop = nullptr;
    napi_create_int32(env, objValue, &prop);
    napi_set_named_property(env, dstObj, propName, prop);
}

napi_value QueryOsAccountById(napi_env env, napi_callback_info cbInfo)
{
    auto queryOAByIdCB = std::make_unique<QueryOAByIdAsyncContext>();
    queryOAByIdCB->env = env;
    queryOAByIdCB->throwErr = true;

    if (!ParseParaQueryOAByIdCB(env, cbInfo, queryOAByIdCB.get())) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (queryOAByIdCB->callbackRef == nullptr) {
        napi_create_promise(env, &queryOAByIdCB->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "QueryOsAccountById", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env,
        nullptr,
        resource,
        QueryOAByIdExecuteCB,
        QueryOAByIdCallbackCompletedCB,
        reinterpret_cast<void *>(queryOAByIdCB.get()),
        &queryOAByIdCB->work);

    napi_queue_async_work_with_qos(env, queryOAByIdCB->work, napi_qos_default);
    queryOAByIdCB.release();
    return result;
}

napi_value RemoveOsAccount(napi_env env, napi_callback_info cbInfo)
{
    auto removeOACB = std::make_unique<RemoveOAAsyncContext>();
    removeOACB->env = env;
    removeOACB->throwErr = true;

    if (!ParseParaRemoveOACB(env, cbInfo, removeOACB.get())) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (removeOACB->callbackRef == nullptr) {
        napi_create_promise(env, &removeOACB->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "RemoveOsAccount", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env, nullptr, resource, RemoveOAExecuteCB, RemoveOACallbackCompletedCB,
        reinterpret_cast<void *>(removeOACB.get()), &removeOACB->work);

    napi_queue_async_work_with_qos(env, removeOACB->work, napi_qos_user_initiated);
    removeOACB.release();
    return result;
}

napi_value SetOsAccountName(napi_env env, napi_callback_info cbInfo)
{
    auto setOANameCB = std::make_unique<SetOANameAsyncContext>();
    setOANameCB->env = env;
    setOANameCB->throwErr = true;

    if (!ParseParaSetOAName(env, cbInfo, setOANameCB.get())) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (setOANameCB->callbackRef == nullptr) {
        napi_create_promise(env, &setOANameCB->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "SetOsAccountName", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env,
        nullptr,
        resource,
        SetOANameExecuteCB,
        SetOANameCallbackCompletedCB,
        reinterpret_cast<void *>(setOANameCB.get()),
        &setOANameCB->work);

    napi_queue_async_work_with_qos(env, setOANameCB->work, napi_qos_user_initiated);
    setOANameCB.release();
    return result;
}

napi_value SetOsAccountConstraints(napi_env env, napi_callback_info cbInfo)
{
    auto setOAConsCB = std::make_unique<SetOAConsAsyncContext>();
    setOAConsCB->env = env;
    setOAConsCB->throwErr = true;

    if (!ParseParaSetOAConstraints(env, cbInfo, setOAConsCB.get())) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (setOAConsCB->callbackRef == nullptr) {
        napi_create_promise(env, &setOAConsCB->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "SetOsAccountConstraints", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env,
        nullptr,
        resource,
        SetOAConsExecuteCB,
        SetOAConsCallbackCompletedCB,
        reinterpret_cast<void *>(setOAConsCB.get()),
        &setOAConsCB->work);

    napi_queue_async_work_with_qos(env, setOAConsCB->work, napi_qos_default);
    setOAConsCB.release();
    return result;
}

napi_value ActivateOsAccount(napi_env env, napi_callback_info cbInfo)
{
    auto activeOACB = std::make_unique<ActivateOAAsyncContext>();
    activeOACB->env = env;
    activeOACB->throwErr = true;

    if (!ParseParaActiveOA(env, cbInfo, activeOACB.get())) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (activeOACB->callbackRef == nullptr) {
        napi_create_promise(env, &activeOACB->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "ActivateOsAccount", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env,
        nullptr,
        resource,
        ActivateOAExecuteCB,
        ActivateOACallbackCompletedCB,
        reinterpret_cast<void *>(activeOACB.get()),
        &activeOACB->work);

    napi_queue_async_work_with_qos(env, activeOACB->work, napi_qos_user_initiated);
    activeOACB.release();
    return result;
}

napi_value DeactivateOsAccount(napi_env env, napi_callback_info cbInfo)
{
    auto asyncContext = std::make_unique<ActivateOAAsyncContext>();
    asyncContext->env = env;

    if (!ParseParaDeactivateOA(env, cbInfo, asyncContext.get())) {
        return nullptr;
    }

    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "DeactivateOsAccount", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env, napi_create_async_work(env,
        nullptr,
        resource,
        DeactivateOAExecuteCB,
        DeactivateOACompletedCB,
        reinterpret_cast<void *>(asyncContext.get()),
        &asyncContext->work));

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_user_initiated));
    asyncContext.release();
    return result;
}

napi_value CreateOsAccount(napi_env env, napi_callback_info cbInfo)
{
    auto createOACB = std::make_unique<CreateOAAsyncContext>();
    createOACB->env = env;
    createOACB->throwErr = true;

    if (!ParseParaCreateOA(env, cbInfo, createOACB.get())) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (createOACB->callbackRef == nullptr) {
        napi_create_promise(env, &createOACB->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "CreateOsAccount", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env, nullptr, resource, CreateOAExecuteCB, CreateOACallbackCompletedCB,
        reinterpret_cast<void *>(createOACB.get()), &createOACB->work);

    napi_queue_async_work_with_qos(env, createOACB->work, napi_qos_user_initiated);
    createOACB.release();
    return result;
}

napi_value CreateOsAccountForDomain(napi_env env, napi_callback_info cbInfo)
{
    auto createOAForDomainCB = std::make_unique<CreateOAForDomainAsyncContext>();
    createOAForDomainCB->env = env;
    createOAForDomainCB->throwErr = true;

    if (!ParseParaCreateOAForDomain(env, cbInfo, createOAForDomainCB.get())) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (createOAForDomainCB->callbackRef == nullptr) {
        napi_create_promise(env, &createOAForDomainCB->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "CreateOsAccountForDomain", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env, nullptr, resource, CreateOAForDomainExecuteCB, CreateOAForDomainCompletedCB,
        createOAForDomainCB.get(), &createOAForDomainCB->work);

    napi_queue_async_work_with_qos(env, createOAForDomainCB->work, napi_qos_user_initiated);
    createOAForDomainCB.release();
    return result;
}

napi_value GetOsAccountCount(napi_env env, napi_callback_info cbInfo)
{
    return GetCreatedOsAccountsCountInner(env, cbInfo, true);
}

napi_value GetCreatedOsAccountsCount(napi_env env, napi_callback_info cbInfo)
{
    return GetCreatedOsAccountsCountInner(env, cbInfo, false);
}

napi_value GetCreatedOsAccountsCountInner(napi_env env, napi_callback_info cbInfo, bool throwErr)
{
    auto getOACount = std::make_unique<GetOACountAsyncContext>();
    getOACount->env = env;
    getOACount->throwErr = throwErr;

    if (!ParseParaGetOACount(env, cbInfo, getOACount.get()) && throwErr) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (getOACount->callbackRef == nullptr) {
        napi_create_promise(env, &getOACount->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "GetCreatedOsAccountsCountInner", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env,
        nullptr,
        resource,
        GetOACountExecuteCB,
        GetOACountCallbackCompletedCB,
        reinterpret_cast<void *>(getOACount.get()),
        &getOACount->work);

    napi_queue_async_work_with_qos(env, getOACount->work, napi_qos_default);
    getOACount.release();
    return result;
}

napi_value QueryDistributedVirtualDeviceId(napi_env env, napi_callback_info cbInfo)
{
    return GetDistributedVirtualDeviceIdInner(env, cbInfo, true);
}

napi_value GetDistributedVirtualDeviceId(napi_env env, napi_callback_info cbInfo)
{
    return GetDistributedVirtualDeviceIdInner(env, cbInfo, false);
}

napi_value GetDistributedVirtualDeviceIdInner(napi_env env, napi_callback_info cbInfo, bool throwErr)
{
    auto dbDeviceId = std::make_unique<DbDeviceIdAsyncContext>();
    dbDeviceId->env = env;
    dbDeviceId->throwErr = throwErr;

    if (!ParseParaDbDeviceId(env, cbInfo, dbDeviceId.get()) && throwErr) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (dbDeviceId->callbackRef == nullptr) {
        napi_create_promise(env, &dbDeviceId->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "GetDistributedVirtualDeviceIdInner", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env,
        nullptr,
        resource,
        DbDeviceIdExecuteCB,
        DbDeviceIdCallbackCompletedCB,
        reinterpret_cast<void *>(dbDeviceId.get()),
        &dbDeviceId->work);

    napi_queue_async_work_with_qos(env, dbDeviceId->work, napi_qos_default);
    dbDeviceId.release();
    return result;
}

napi_value GetOsAccountConstraints(napi_env env, napi_callback_info cbInfo)
{
    return GetOsAccountAllConstraintsInner(env, cbInfo, true);
}

napi_value GetOsAccountAllConstraints(napi_env env, napi_callback_info cbInfo)
{
    return GetOsAccountAllConstraintsInner(env, cbInfo, false);
}

napi_value GetOsAccountAllConstraintsInner(napi_env env, napi_callback_info cbInfo, bool throwErr)
{
    auto getAllConsCB = std::make_unique<GetAllConsAsyncContext>();
    getAllConsCB->env = env;
    getAllConsCB->throwErr = throwErr;

    if (!ParseParaGetAllCons(env, cbInfo, getAllConsCB.get()) && throwErr) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (getAllConsCB->callbackRef == nullptr) {
        napi_create_promise(env, &getAllConsCB->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "GetOsAccountAllConstraints", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env,
        nullptr,
        resource,
        GetAllConsExecuteCB,
        GetAllConsCallbackCompletedCB,
        reinterpret_cast<void *>(getAllConsCB.get()),
        &getAllConsCB->work);

    napi_queue_async_work_with_qos(env, getAllConsCB->work, napi_qos_default);
    getAllConsCB.release();
    return result;
}

napi_value QueryOsAccountLocalIdFromProcess(napi_env env, napi_callback_info cbInfo)
{
    return GetOsAccountLocalIdFromProcessInner(env, cbInfo, true);
}

napi_value GetOsAccountLocalIdFromProcess(napi_env env, napi_callback_info cbInfo)
{
    return GetOsAccountLocalIdFromProcessInner(env, cbInfo, false);
}

napi_value GetOsAccountLocalIdFromProcessInner(napi_env env, napi_callback_info cbInfo, bool throwErr)
{
    auto getIdCB = std::make_unique<GetIdAsyncContext>();
    getIdCB->env = env;
    getIdCB->throwErr = throwErr;

    if (!ParseParaProcessId(env, cbInfo, getIdCB.get()) && throwErr) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (getIdCB->callbackRef == nullptr) {
        napi_create_promise(env, &getIdCB->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "GetOsAccountLocalIdFromProcessInner", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env,
        nullptr,
        resource,
        GetProcessIdExecuteCB,
        GetProcessIdCallbackCompletedCB,
        reinterpret_cast<void *>(getIdCB.get()),
        &getIdCB->work);

    napi_queue_async_work_with_qos(env, getIdCB->work, napi_qos_default);
    getIdCB.release();
    return result;
}

napi_value QueryAllCreatedOsAccounts(napi_env env, napi_callback_info cbInfo)
{
    auto queryAllOA = std::make_unique<QueryCreateOAAsyncContext>();
    queryAllOA->env = env;
    queryAllOA->throwErr = true;

    if (!ParseQueryAllCreateOA(env, cbInfo, queryAllOA.get())) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (queryAllOA->callbackRef == nullptr) {
        napi_create_promise(env, &queryAllOA->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "QueryAllCreatedOsAccounts", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env,
        nullptr,
        resource,
        QueryCreateOAExecuteCB,
        QueryCreateOACallbackCompletedCB,
        reinterpret_cast<void *>(queryAllOA.get()),
        &queryAllOA->work);

    napi_queue_async_work_with_qos(env, queryAllOA->work, napi_qos_default);
    queryAllOA.release();
    return result;
}

napi_value QueryOsAccountConstraintSourceTypes(napi_env env, napi_callback_info cbInfo)
{
    auto queryConstraintSource = std::make_unique<QueryOAConstraintSrcTypeContext>();
    queryConstraintSource->env = env;
    queryConstraintSource->throwErr = true;

    if (!ParseQueryOAConstraintSrcTypes(env, cbInfo, queryConstraintSource.get())) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (queryConstraintSource->callbackRef == nullptr) {
        napi_create_promise(env, &queryConstraintSource->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "QueryOsAccountConstraintSourceTypes", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env,
        nullptr,
        resource,
        QueryOAContSrcTypeExecuteCB,
        QueryOAContSrcTypeCallbackCompletedCB,
        reinterpret_cast<void *>(queryConstraintSource.get()),
        &queryConstraintSource->work);

    napi_queue_async_work_with_qos(env, queryConstraintSource->work, napi_qos_default);
    queryConstraintSource.release();
    return result;
}

napi_value GetActivatedOsAccountIds(napi_env env, napi_callback_info cbInfo)
{
    return QueryActivatedOsAccountIdsInner(env, cbInfo, true);
}

napi_value QueryActivatedOsAccountIds(napi_env env, napi_callback_info cbInfo)
{
    return QueryActivatedOsAccountIdsInner(env, cbInfo, false);
}

napi_value QueryActivatedOsAccountIdsInner(napi_env env, napi_callback_info cbInfo, bool throwErr)
{
    auto queryActiveIds = std::make_unique<QueryActiveIdsAsyncContext>();
    queryActiveIds->env = env;
    queryActiveIds->throwErr = throwErr;

    if (!ParseQueryActiveIds(env, cbInfo, queryActiveIds.get()) && throwErr) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (queryActiveIds->callbackRef == nullptr) {
        napi_create_promise(env, &queryActiveIds->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "QueryActivatedOsAccountIdsInner", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env,
        nullptr,
        resource,
        QueryActiveIdsExecuteCB,
        QueryActiveIdsCallbackCompletedCB,
        reinterpret_cast<void *>(queryActiveIds.get()),
        &queryActiveIds->work);

    napi_queue_async_work_with_qos(env, queryActiveIds->work, napi_qos_default);
    queryActiveIds.release();
    return result;
}

napi_value GetForegroundOsAccountLocalId(napi_env env, napi_callback_info cbInfo)
{
    auto getForegroundIds = std::make_unique<GetForegroundOALocalIdAsyncContext>();
    getForegroundIds->env = env;
    getForegroundIds->throwErr = true;

    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &getForegroundIds->deferred, &result));

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GetForegroundOsAccountLocalId", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env, napi_create_async_work(env,
        nullptr,
        resource,
        GetForegroundOALocalIdExecuteCB,
        GetForegroundOALocalIdCallbackCompletedCB,
        reinterpret_cast<void *>(getForegroundIds.get()),
        &getForegroundIds->work));

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, getForegroundIds->work, napi_qos_default));
    getForegroundIds.release();
    return result;
}

napi_value GetOsAccountName(napi_env env, napi_callback_info cbInfo)
{
    auto context = std::make_unique<GetOsAccountNameContext>();
    context->env = env;

    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &context->deferred, &result));
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GetOsAccountName", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, GetOsAccountNameExecuteCB,
        GetOsAccountNameCallbackCompletedCB,
        reinterpret_cast<void *>(context.get()), &context->work));

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, context->work, napi_qos_default));
    context.release();
    return result;
}

napi_value GetOsAccountProfilePhoto(napi_env env, napi_callback_info cbInfo)
{
    auto getPhoto = std::make_unique<GetOAPhotoAsyncContext>();
    getPhoto->env = env;
    getPhoto->throwErr = true;

    if (!ParseParaGetPhoto(env, cbInfo, getPhoto.get())) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (getPhoto->callbackRef == nullptr) {
        napi_create_promise(env, &getPhoto->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "GetOsAccountProfilePhoto", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env, nullptr, resource, GetOAPhotoExecuteCB, GetOAPhotoCallbackCompletedCB,
        reinterpret_cast<void *>(getPhoto.get()), &getPhoto->work);

    napi_queue_async_work_with_qos(env, getPhoto->work, napi_qos_default);
    getPhoto.release();
    return result;
}

napi_value GetCurrentOsAccount(napi_env env, napi_callback_info cbInfo)
{
    return QueryCurrentOsAccountInner(env, cbInfo, true);
}

napi_value QueryCurrentOsAccount(napi_env env, napi_callback_info cbInfo)
{
    return QueryCurrentOsAccountInner(env, cbInfo, false);
}

napi_value QueryCurrentOsAccountInner(napi_env env, napi_callback_info cbInfo, bool throwErr)
{
    auto currentOA = std::make_unique<CurrentOAAsyncContext>();
    currentOA->env = env;
    currentOA->throwErr = throwErr;

    if (!ParseParaCurrentOA(env, cbInfo, currentOA.get()) && throwErr) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (currentOA->callbackRef == nullptr) {
        napi_create_promise(env, &currentOA->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "QueryCurrentOsAccount", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env,
        nullptr,
        resource,
        QueryCurrentOAExecuteCB,
        QueryCurrentOACallbackCompletedCB,
        reinterpret_cast<void *>(currentOA.get()),
        &currentOA->work);

    napi_queue_async_work_with_qos(env, currentOA->work, napi_qos_default);
    currentOA.release();
    return result;
}

napi_value GetOsAccountLocalIdFromUidInner(napi_env env, napi_callback_info cbInfo, bool throwErr)
{
    auto idByUid = std::make_unique<GetIdByUidAsyncContext>();
    idByUid->env = env;
    idByUid->throwErr = throwErr;

    if (!ParseParaGetIdByUid(env, cbInfo, idByUid.get()) && throwErr) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (idByUid->callbackRef == nullptr) {
        napi_create_promise(env, &idByUid->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "GetOsAccountLocalIdFromUidInner", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env, nullptr, resource, GetIdByUidExecuteCB, GetIdByUidCallbackCompletedCB,
        reinterpret_cast<void *>(idByUid.get()), &idByUid->work);

    napi_queue_async_work_with_qos(env, idByUid->work, napi_qos_default);
    idByUid.release();
    return result;
}

napi_value GetOsAccountLocalIdFromUid(napi_env env, napi_callback_info cbInfo)
{
    return GetOsAccountLocalIdFromUidInner(env, cbInfo, false);
}

napi_value GetOsAccountLocalIdForUid(napi_env env, napi_callback_info cbInfo)
{
    return GetOsAccountLocalIdFromUidInner(env, cbInfo, true);
}

static bool ParseUidFromCbInfo(napi_env env, napi_callback_info cbInfo, int32_t &uid)
{
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc == 0) {
        ACCOUNT_LOGE("The number of parameters should be at least 1.");
        std::string errMsg = "Parameter error. The number of parameters should be at least 1";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    if (!GetIntProperty(env, argv[0], uid)) {
        ACCOUNT_LOGE("Get uid failed.");
        std::string errMsg = "Parameter error. The type of \"uid\" must be number";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    return true;
}

napi_value GetOsAccountLocalIdForUidSync(napi_env env, napi_callback_info cbInfo)
{
    napi_value napiValue = nullptr;
    int32_t uid = 0;
    if (!ParseUidFromCbInfo(env, cbInfo, uid)) {
        return napiValue;
    }
    int32_t localId = 0;
    ErrCode errCode = OsAccountManager::GetOsAccountLocalIdFromUid(uid, localId);
    if (errCode != ERR_OK) {
        AccountNapiThrow(env, errCode);
        return napiValue;
    }
    NAPI_CALL(env, napi_create_int32(env, localId, &napiValue));
    return napiValue;
}

napi_value GetBundleIdFromUid(napi_env env, napi_callback_info cbInfo)
{
    auto bundleIdByUid = std::make_unique<GetIdByUidAsyncContext>();
    bundleIdByUid->env = env;
    bundleIdByUid->throwErr = true;

    if (!ParseParaGetIdByUid(env, cbInfo, bundleIdByUid.get())) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (bundleIdByUid->callbackRef == nullptr) {
        napi_create_promise(env, &bundleIdByUid->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "GetBundleIdFromUid", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env, nullptr, resource,
        GetBundleIdByUidExecuteCB,
        GetBundleIdByUidCallbackCompletedCB,
        reinterpret_cast<void *>(bundleIdByUid.get()),
        &bundleIdByUid->work);

    napi_queue_async_work_with_qos(env, bundleIdByUid->work, napi_qos_default);
    bundleIdByUid.release();
    return result;
}

napi_value GetBundleIdForUidSync(napi_env env, napi_callback_info cbInfo)
{
    napi_value retValue = nullptr;
    int32_t uid = 0;
    if (!ParseUidFromCbInfo(env, cbInfo, uid)) {
        return retValue;
    }
    int32_t bundleId = 0;
    ErrCode errCode = OsAccountManager::GetBundleIdFromUid(uid, bundleId);
    if (errCode != ERR_OK) {
        AccountNapiThrow(env, errCode);
        return retValue;
    }
    NAPI_CALL(env, napi_create_int32(env, bundleId, &retValue));
    return retValue;
}

napi_value QueryOsAccountLocalIdFromDomain(napi_env env, napi_callback_info cbInfo)
{
    return GetOsAccountLocalIdFromDomainInner(env, cbInfo, true);
}

napi_value GetOsAccountLocalIdFromDomain(napi_env env, napi_callback_info cbInfo)
{
    return GetOsAccountLocalIdFromDomainInner(env, cbInfo, false);
}

napi_value GetOsAccountLocalIdFromDomainInner(napi_env env, napi_callback_info cbInfo, bool throwErr)
{
    auto idByDomain = std::make_unique<GetIdByDomainAsyncContext>();
    idByDomain->env = env;
    idByDomain->throwErr = throwErr;

    if (!ParseParaGetIdByDomain(env, cbInfo, idByDomain.get()) && throwErr) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (idByDomain->callbackRef == nullptr) {
        napi_create_promise(env, &idByDomain->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "GetOsAccountLocalIdFromDomainInner", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env, nullptr, resource, GetIdByDomainExecuteCB, GetIdByDomainCallbackCompletedCB,
        reinterpret_cast<void *>(idByDomain.get()), &idByDomain->work);

    napi_queue_async_work_with_qos(env, idByDomain->work, napi_qos_default);
    idByDomain.release();
    return result;
}

napi_value SetOsAccountProfilePhoto(napi_env env, napi_callback_info cbInfo)
{
    auto setPhoto = std::make_unique<SetOAPhotoAsyncContext>();
    setPhoto->env = env;
    setPhoto->throwErr = true;

    if (!ParseParaSetPhoto(env, cbInfo, setPhoto.get())) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (setPhoto->callbackRef == nullptr) {
        napi_create_promise(env, &setPhoto->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "SetOsAccountProfilePhoto", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env, nullptr, resource, SetPhotoExecuteCB, SetPhotoCompletedCB,
        reinterpret_cast<void *>(setPhoto.get()), &setPhoto->work);

    napi_queue_async_work_with_qos(env, setPhoto->work, napi_qos_user_initiated);
    setPhoto.release();
    return result;
}

napi_value QueryMaxOsAccountNumber(napi_env env, napi_callback_info cbInfo)
{
    auto maxNum = std::make_unique<QueryMaxNumAsyncContext>();
    maxNum->env = env;
    maxNum->throwErr = true;

    if (!ParseParaQueryMaxNum(env, cbInfo, maxNum.get())) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (maxNum->callbackRef == nullptr) {
        napi_create_promise(env, &maxNum->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "QueryMaxOsAccountNumber", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env, nullptr, resource, QueryMaxNumExecuteCB, QueryMaxNumCompletedCB,
        reinterpret_cast<void *>(maxNum.get()), &maxNum->work);

    napi_queue_async_work_with_qos(env, maxNum->work, napi_qos_default);
    maxNum.release();
    return result;
}

napi_value QueryMaxLoggedInOsAccountNumber(napi_env env, napi_callback_info cbInfo)
{
    auto context = std::make_unique<QueryMaxNumAsyncContext>();
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &context->deferred, &result));
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "QueryMaxLoggedInOsAccountNumber", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource,
        [](napi_env env, void *data) {
            auto context = reinterpret_cast<QueryMaxNumAsyncContext *>(data);
            context->errCode = OsAccountManager::QueryMaxLoggedInOsAccountNumber(context->maxLoggedInNumber);
        }, [](napi_env env, napi_status status, void *data) {
            auto context = reinterpret_cast<QueryMaxNumAsyncContext *>(data);
            napi_value errJs = nullptr;
            napi_value dataJs = nullptr;
            if (context->errCode == napi_ok) {
                napi_create_uint32(env, context->maxLoggedInNumber, &dataJs);
            } else {
                errJs = GenerateBusinessError(env, context->errCode);
            }
            ProcessCallbackOrPromise(env, context, errJs, dataJs);
            delete context;
        }, reinterpret_cast<void *>(context.get()), &context->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, context->work, napi_qos_default));
    context.release();
    return result;
}

napi_value InnerIsOsAccountActived(napi_env env, napi_callback_info cbInfo, bool throwErr)
{
    auto isActived = std::make_unique<IsActivedAsyncContext>();
    isActived->env = env;
    isActived->throwErr = throwErr;

    if (!ParseParaIsActived(env, cbInfo, isActived.get()) && throwErr) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (isActived->callbackRef == nullptr) {
        napi_create_promise(env, &isActived->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "IsOsAccountActived", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env, nullptr, resource, IsActivedExecuteCB, IsActivedCompletedCB,
        reinterpret_cast<void *>(isActived.get()), &isActived->work);

    napi_queue_async_work_with_qos(env, isActived->work, napi_qos_default);
    isActived.release();
    return result;
}

napi_value CheckOsAccountActivated(napi_env env, napi_callback_info cbInfo)
{
    return InnerIsOsAccountActived(env, cbInfo, true);
}

napi_value IsOsAccountActived(napi_env env, napi_callback_info cbInfo)
{
    return InnerIsOsAccountActived(env, cbInfo, false);
}

napi_value InnerIsOsAccountConstraintEnable(napi_env env, napi_callback_info cbInfo, bool throwErr)
{
    auto isEnable = std::make_unique<IsConEnableAsyncContext>();
    isEnable->env = env;
    isEnable->throwErr = throwErr;

    if (!ParseParaIsEnable(env, cbInfo, isEnable.get()) && throwErr) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (isEnable->callbackRef == nullptr) {
        napi_create_promise(env, &isEnable->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "IsOsAccountConstraintEnable", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env, nullptr, resource, IsEnableExecuteCB, IsEnableCompletedCB,
        reinterpret_cast<void *>(isEnable.get()), &isEnable->work);

    napi_queue_async_work_with_qos(env, isEnable->work, napi_qos_default);
    isEnable.release();
    return result;
}

napi_value IsOsAccountConstraintEnable(napi_env env, napi_callback_info cbInfo)
{
    return InnerIsOsAccountConstraintEnable(env, cbInfo, false);
}

napi_value CheckConstraintEnabled(napi_env env, napi_callback_info cbInfo)
{
    return InnerIsOsAccountConstraintEnable(env, cbInfo, true);
}

napi_value GetOsAccountType(napi_env env, napi_callback_info cbInfo)
{
    return GetOsAccountTypeFromProcessInner(env, cbInfo, true);
}

napi_value GetOsAccountTypeFromProcess(napi_env env, napi_callback_info cbInfo)
{
    return GetOsAccountTypeFromProcessInner(env, cbInfo, false);
}

napi_value GetOsAccountTypeFromProcessInner(napi_env env, napi_callback_info cbInfo, bool throwErr)
{
    auto getType = std::make_unique<GetTypeAsyncContext>();
    getType->env = env;
    getType->throwErr = throwErr;

    if (!ParseParaGetType(env, cbInfo, getType.get()) && throwErr) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (getType->callbackRef == nullptr) {
        napi_create_promise(env, &getType->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "GetOsAccountTypeFromProcessInner", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env, nullptr, resource, GetTypeExecuteCB, GetTypeCompletedCB,
        reinterpret_cast<void *>(getType.get()), &getType->work);

    napi_queue_async_work_with_qos(env, getType->work, napi_qos_default);
    getType.release();
    return result;
}

napi_value IsMultiOsAccountEnable(napi_env env, napi_callback_info cbInfo)
{
    return InnerIsMultiOsAccountEnable(env, cbInfo, false);
}

napi_value CheckMultiOsAccountEnabled(napi_env env, napi_callback_info cbInfo)
{
    return InnerIsMultiOsAccountEnable(env, cbInfo, true);
}

napi_value InnerIsMultiOsAccountEnable(napi_env env, napi_callback_info cbInfo, bool throwErr)
{
    auto multiEn = std::make_unique<IsMultiEnAsyncContext>();
    multiEn->env = env;
    multiEn->throwErr = throwErr;

    if (!ParseParaIsMultiEn(env, cbInfo, multiEn.get()) && throwErr) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (multiEn->callbackRef == nullptr) {
        napi_create_promise(env, &multiEn->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "IsMultiOsAccountEnable", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env, nullptr, resource, IsMultiEnExecuteCB, IsMultiEnCompletedCB,
        reinterpret_cast<void *>(multiEn.get()), &multiEn->work);

    napi_queue_async_work_with_qos(env, multiEn->work, napi_qos_default);
    multiEn.release();
    return result;
}

napi_value InnerIsOsAccountVerified(napi_env env, napi_callback_info cbInfo, bool throwErr)
{
    auto isVerified = std::make_unique<IsVerifiedAsyncContext>();
    isVerified->env = env;
    isVerified->throwErr = throwErr;

    if (!ParseParaIsVerified(env, cbInfo, isVerified.get()) && throwErr) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (isVerified->callbackRef == nullptr) {
        napi_create_promise(env, &isVerified->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "IsOsAccountVerified", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env, nullptr, resource, IsVerifiedExecuteCB, IsVerifiedCompletedCB,
        reinterpret_cast<void *>(isVerified.get()), &isVerified->work);

    napi_queue_async_work_with_qos(env, isVerified->work, napi_qos_default);
    isVerified.release();
    return result;
}

napi_value IsOsAccountVerified(napi_env env, napi_callback_info cbInfo)
{
    return InnerIsOsAccountVerified(env, cbInfo, false);
}

napi_value CheckOsAccountVerified(napi_env env, napi_callback_info cbInfo)
{
    return InnerIsOsAccountVerified(env, cbInfo, true);
}

napi_value QueryOsAccountLocalIdBySerialNumber(napi_env env, napi_callback_info cbInfo)
{
    return GetOsAccountLocalIdBySerialNumberInner(env, cbInfo, true);
}

napi_value GetOsAccountLocalIdBySerialNumber(napi_env env, napi_callback_info cbInfo)
{
    return GetOsAccountLocalIdBySerialNumberInner(env, cbInfo, false);
}

napi_value GetOsAccountLocalIdBySerialNumberInner(napi_env env, napi_callback_info cbInfo, bool throwErr)
{
    auto serialNumId = std::make_unique<GetSerialNumIdCBInfo>();
    serialNumId->env = env;
    serialNumId->throwErr = throwErr;

    if (!ParseParaSerialNumId(env, cbInfo, serialNumId.get()) && throwErr) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (serialNumId->callbackRef == nullptr) {
        napi_create_promise(env, &serialNumId->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "GetOsAccountLocalIdBySerialNumberInner", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env, nullptr, resource, SerialNumIdExecuteCB, SerialNumIdCompletedCB,
        reinterpret_cast<void *>(serialNumId.get()), &serialNumId->work);

    napi_queue_async_work_with_qos(env, serialNumId->work, napi_qos_default);
    serialNumId.release();
    return result;
}

napi_value QuerySerialNumberByOsAccountLocalId(napi_env env, napi_callback_info cbInfo)
{
    return GetSerialNumberByOsAccountLocalIdInner(env, cbInfo, true);
}

napi_value GetSerialNumberByOsAccountLocalId(napi_env env, napi_callback_info cbInfo)
{
    return GetSerialNumberByOsAccountLocalIdInner(env, cbInfo, false);
}

napi_value GetSerialNumberByOsAccountLocalIdInner(napi_env env, napi_callback_info cbInfo, bool throwErr)
{
    auto getSerialNum = std::make_unique<GetSerialNumForOAInfo>();
    getSerialNum->env = env;
    getSerialNum->throwErr = throwErr;

    if (!ParseParaGetSerialNum(env, cbInfo, getSerialNum.get()) && throwErr) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (getSerialNum->callbackRef == nullptr) {
        napi_create_promise(env, &getSerialNum->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "GetSerialNumberByOsAccountLocalId", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env,
        nullptr,
        resource,
        GetSerialNumExecuteCB,
        GetSerialNumCompletedCB,
        reinterpret_cast<void *>(getSerialNum.get()),
        &getSerialNum->work);

    napi_queue_async_work_with_qos(env, getSerialNum->work, napi_qos_default);
    getSerialNum.release();
    return result;
}

napi_value IsTestOsAccount(napi_env env, napi_callback_info cbInfo)
{
    return InnerIsTestOsAccount(env, cbInfo, false);
}

napi_value CheckOsAccountTestable(napi_env env, napi_callback_info cbInfo)
{
    return InnerIsTestOsAccount(env, cbInfo, true);
}

napi_value InnerIsTestOsAccount(napi_env env, napi_callback_info cbInfo, bool throwErr)
{
    auto isTest = std::make_unique<IsTestOAInfo>();
    isTest->env = env;
    isTest->throwErr = throwErr;

    if (!ParseParaIsTestOA(env, cbInfo, isTest.get()) && throwErr) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (isTest->callbackRef == nullptr) {
        napi_create_promise(env, &isTest->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "IsTestOsAccount", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env,
        nullptr,
        resource,
        [](napi_env env, void *data) {},
        [](napi_env env, napi_status status, void *data) {
            ACCOUNT_LOGI("napi_create_async_work complete");
            IsTestOAInfo *isTest = reinterpret_cast<IsTestOAInfo *>(data);
            isTest->errCode = 0;
            isTest->isTestOsAccount = false;
            napi_value result[RESULT_COUNT] = {0};
            result[PARAMZERO] = GenerateBusinessSuccess(env, isTest->throwErr);
            napi_get_boolean(env, isTest->isTestOsAccount, &result[PARAMONE]);
            ProcessCallbackOrPromise(env, isTest, result[PARAMZERO], result[PARAMONE]);
            delete isTest;
        },
        reinterpret_cast<void *>(isTest.get()),
        &isTest->work);
    napi_queue_async_work_with_qos(env, isTest->work, napi_qos_default);
    isTest.release();
    return result;
}

napi_value IsMainOsAccount(napi_env env, napi_callback_info cbInfo)
{
    auto isMain = std::make_unique<IsMainOAInfo>();
    isMain->env = env;
    isMain->throwErr = true;

    if (!ParseParaIsMainOA(env, cbInfo, isMain.get())) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (isMain->callbackRef == nullptr) {
        napi_create_promise(env, &isMain->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "IsMainOsAccount", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env,
        nullptr,
        resource,
        [](napi_env env, void *data) {
            IsMainOAInfo *isMain = reinterpret_cast<IsMainOAInfo *>(data);
            isMain->errCode = OsAccountManager::IsMainOsAccount(isMain->isMainOsAccount);
            ACCOUNT_LOGD("error code is %{public}d", isMain->errCode);
            isMain->status = (isMain->errCode == 0) ? napi_ok : napi_generic_failure;
        },
        [](napi_env env, napi_status status, void *data) {
            ACCOUNT_LOGD("napi_create_async_work complete");
            IsMainOAInfo *isMain = reinterpret_cast<IsMainOAInfo *>(data);
            napi_value result[RESULT_COUNT] = {0};
            result[PARAMZERO] = GenerateBusinessError(env, isMain->errCode);
            napi_get_boolean(env, isMain->isMainOsAccount, &result[PARAMONE]);
            ProcessCallbackOrPromise(env, isMain, result[PARAMZERO], result[PARAMONE]);
            delete isMain;
        },
        reinterpret_cast<void *>(isMain.get()),
        &isMain->work);

    napi_queue_async_work_with_qos(env, isMain->work, napi_qos_default);
    isMain.release();
    return result;
}

static bool IsSubscribeInMap(napi_env env, SubscribeCBInfo *subscribeCBInfo)
{
    std::lock_guard<std::mutex> lock(g_lockForOsAccountSubscribers);
    auto subscribe = g_osAccountSubscribers.find(subscribeCBInfo->osManager);
    if (subscribe == g_osAccountSubscribers.end()) {
        return false;
    }
    auto it = subscribe->second.begin();
    while (it != subscribe->second.end()) {
        if (((*it)->osSubscribeType == subscribeCBInfo->osSubscribeType) &&
            (CompareOnAndOffRef(env, (*it)->callbackRef, subscribeCBInfo->callbackRef))) {
            return true;
        }
        it++;
    }
    return false;
}

napi_value Subscribe(napi_env env, napi_callback_info cbInfo)
{
    SubscribeCBInfo *subscribeCBInfo = new (std::nothrow) SubscribeCBInfo(env);
    if (subscribeCBInfo == nullptr) {
        ACCOUNT_LOGE("insufficient memory for subscribeCBInfo!");
        return nullptr;
    }
    subscribeCBInfo->throwErr = true;

    napi_value thisVar = nullptr;

    if (!ParseParaToSubscriber(env, cbInfo, subscribeCBInfo, &thisVar)) {
        delete subscribeCBInfo;
        ACCOUNT_LOGE("Parse subscribe failed");
        return nullptr;
    }

    // make osaccount subscribe info
    OsAccountSubscribeInfo subscribeInfo(subscribeCBInfo->osSubscribeType, subscribeCBInfo->name);
    // make a subscriber
    subscribeCBInfo->subscriber = std::make_shared<SubscriberPtr>(subscribeInfo);

    OsAccountManager *objectInfo = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&objectInfo));
    subscribeCBInfo->osManager = objectInfo;
    subscribeCBInfo->subscriber->SetEnv(env);
    subscribeCBInfo->subscriber->SetCallbackRef(subscribeCBInfo->callbackRef);
    if (IsSubscribeInMap(env, subscribeCBInfo)) {
        delete subscribeCBInfo;
        return WrapVoidToJS(env);
    }
    ErrCode errCode = OsAccountManager::SubscribeOsAccount(subscribeCBInfo->subscriber);
    if (errCode != ERR_OK) {
        delete subscribeCBInfo;
        AccountNapiThrow(env, errCode, true);
        return WrapVoidToJS(env);
    } else {
        std::lock_guard<std::mutex> lock(g_lockForOsAccountSubscribers);
        g_osAccountSubscribers[objectInfo].emplace_back(subscribeCBInfo);
    }
    return WrapVoidToJS(env);
}

SubscriberPtr::SubscriberPtr(const OsAccountSubscribeInfo &subscribeInfo) : OsAccountSubscriber(subscribeInfo)
{}

SubscriberPtr::~SubscriberPtr()
{}

void SubscriberPtr::OnAccountsChanged(const int &id)
{
    OnAccountsSubNotify(id, id);
}

void SubscriberPtr::OnAccountsSwitch(const int &newId, const int &oldId)
{
    OnAccountsSubNotify(newId, oldId);
}

void SubscriberPtr::OnAccountsSubNotify(const int &newId, const int &oldId)
{
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (loop == nullptr) {
        ACCOUNT_LOGE("loop instance is nullptr");
        return;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        ACCOUNT_LOGE("insufficient memory for work!");
        return;
    }
    SubscriberOAWorker *subscriberOAWorker = new (std::nothrow) SubscriberOAWorker();
    if (subscriberOAWorker == nullptr) {
        ACCOUNT_LOGE("insufficient memory for SubscriberAccountsWorker!");
        delete work;
        return;
    }
    subscriberOAWorker->oldId = oldId;
    subscriberOAWorker->newId = newId;
    subscriberOAWorker->env = env_;
    subscriberOAWorker->ref = ref_;
    subscriberOAWorker->subscriber = this;
    work->data = reinterpret_cast<void *>(subscriberOAWorker);
    int32_t ret =
        uv_queue_work_with_qos(loop, work, [](uv_work_t *work) {}, UvQueueWorkOnAccountsSubNotify, uv_qos_default);
    if (ret != 0) {
        ACCOUNT_LOGE("failed to uv_queue_work_with_qos, errCode: %{public}d", ret);
        delete work;
        delete subscriberOAWorker;
    }
}

static napi_value CreateSwitchEventInfoObj(std::unique_ptr<SubscriberOAWorker> &subscriberOAWorker)
{
    napi_env env = subscriberOAWorker->env;
    napi_value objInfo = nullptr;
    NAPI_CALL(env, napi_create_object(env, &objInfo));
    napi_value fromAccountIdJs;
    NAPI_CALL(env, napi_create_int32(env, subscriberOAWorker->oldId, &fromAccountIdJs));
    NAPI_CALL(env, napi_set_named_property(env, objInfo, "fromAccountId", fromAccountIdJs));
    napi_value toAccountIdJs;
    NAPI_CALL(env, napi_create_int32(env, subscriberOAWorker->newId, &toAccountIdJs));
    NAPI_CALL(env, napi_set_named_property(env, objInfo, "toAccountId", toAccountIdJs));

    return objInfo;
}

void UvQueueWorkOnAccountsSubNotify(uv_work_t *work, int status)
{
    std::unique_ptr<uv_work_t> workPtr(work);
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
        return;
    }
    std::unique_ptr<SubscriberOAWorker> subscriberOAWorkerData(reinterpret_cast<SubscriberOAWorker *>(work->data));
    bool isFound = false;
    {
        std::lock_guard<std::mutex> lock(g_lockForOsAccountSubscribers);
        SubscriberPtr *subscriber = subscriberOAWorkerData->subscriber;
        for (auto subscriberInstance : g_osAccountSubscribers) {
            isFound = std::any_of(subscriberInstance.second.begin(), subscriberInstance.second.end(),
                [subscriber](const SubscribeCBInfo *item) {
                    return item->subscriber.get() == subscriber;
                });
            if (isFound) {
                ACCOUNT_LOGD("os account subscriber has been found.");
                break;
            }
        }
    }
    if (isFound) {
        OsAccountSubscribeInfo subscribeInfo;
        OS_ACCOUNT_SUBSCRIBE_TYPE osSubscribeType;
        subscriberOAWorkerData->subscriber->GetSubscribeInfo(subscribeInfo);
        subscribeInfo.GetOsAccountSubscribeType(osSubscribeType);

        napi_value result[ARGS_SIZE_ONE] = {nullptr};
        if ((osSubscribeType == SWITCHING || osSubscribeType == SWITCHED)) {
            ACCOUNT_LOGI("Switch condition, return oldId=%{public}d and newId=%{public}d.",
                         subscriberOAWorkerData->oldId, subscriberOAWorkerData->newId);
            result[PARAMZERO] = CreateSwitchEventInfoObj(subscriberOAWorkerData);
        } else {
            napi_create_int32(subscriberOAWorkerData->env, subscriberOAWorkerData->newId, &result[PARAMZERO]);
        }
        napi_value undefined = nullptr;
        napi_get_undefined(subscriberOAWorkerData->env, &undefined);
        napi_value callback = nullptr;
        napi_get_reference_value(subscriberOAWorkerData->env, subscriberOAWorkerData->ref, &callback);
        napi_value resultOut = nullptr;
        napi_call_function(
            subscriberOAWorkerData->env, undefined, callback, ARGS_SIZE_ONE, &result[0], &resultOut);
    }
    napi_close_handle_scope(subscriberOAWorkerData->env, scope);
}

void SubscriberPtr::SetEnv(const napi_env &env)
{
    env_ = env;
}

void SubscriberPtr::SetCallbackRef(const napi_ref &ref)
{
    ref_ = ref;
}

napi_value Unsubscribe(napi_env env, napi_callback_info cbInfo)
{
    UnsubscribeCBInfo *unsubscribeCBInfo = new (std::nothrow) UnsubscribeCBInfo(env);
    if (unsubscribeCBInfo == nullptr) {
        ACCOUNT_LOGE("insufficient memory for unsubscribeCBInfo!");
        return WrapVoidToJS(env);
    }
    unsubscribeCBInfo->callbackRef = nullptr;
    unsubscribeCBInfo->throwErr = true;

    napi_value thisVar = nullptr;

    if (!ParseParaToUnsubscriber(env, cbInfo, unsubscribeCBInfo, &thisVar)) {
        delete unsubscribeCBInfo;
        ACCOUNT_LOGE("Parse unsubscribe failed");
        return nullptr;
    }

    OsAccountManager *objectInfo = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&objectInfo));
    unsubscribeCBInfo->osManager = objectInfo;

    UnsubscribeSync(env, unsubscribeCBInfo);
    delete unsubscribeCBInfo;
    return WrapVoidToJS(env);
}

void UnsubscribeSync(napi_env env, UnsubscribeCBInfo *unsubscribeCBInfo)
{
    std::lock_guard<std::mutex> lock(g_lockForOsAccountSubscribers);
    auto subscribe = g_osAccountSubscribers.find(unsubscribeCBInfo->osManager);
    if (subscribe == g_osAccountSubscribers.end()) {
        return;
    }
    auto item = subscribe->second.begin();
    while (item != subscribe->second.end()) {
        OsAccountSubscribeInfo subscribeInfo;
        OS_ACCOUNT_SUBSCRIBE_TYPE osSubscribeType;
        std::string name;
        (*item)->subscriber->GetSubscribeInfo(subscribeInfo);
        subscribeInfo.GetOsAccountSubscribeType(osSubscribeType);
        subscribeInfo.GetName(name);
        if (((unsubscribeCBInfo->osSubscribeType != osSubscribeType) || (unsubscribeCBInfo->name != name)) ||
            ((unsubscribeCBInfo->callbackRef != nullptr) &&
            (!CompareOnAndOffRef(env, (*item)->callbackRef, unsubscribeCBInfo->callbackRef)))) {
            item++;
            continue;
        }
        int errCode = OsAccountManager::UnsubscribeOsAccount((*item)->subscriber);
        if (errCode != ERR_OK) {
            AccountNapiThrow(env, errCode, true);
            return;
        }
        delete (*item);
        item = subscribe->second.erase(item);
        if (unsubscribeCBInfo->callbackRef != nullptr) {
            break;
        }
    }
    if (subscribe->second.empty()) {
        g_osAccountSubscribers.erase(subscribe->first);
    }
}

napi_value IsOsAccountActivated(napi_env env, napi_callback_info cbInfo)
{
    if (AccountPermissionManager::CheckSystemApp(false) != ERR_OK) {
        AccountNapiThrow(env, ERR_JS_IS_NOT_SYSTEM_APP);
        return nullptr;
    }
    return InnerIsOsAccountActived(env, cbInfo, true);
}

napi_value IsOsAccountConstraintEnabled(napi_env env, napi_callback_info cbInfo)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    if (argc == ARGS_SIZE_TWO && AccountPermissionManager::CheckSystemApp(false) != ERR_OK) {
        AccountNapiThrow(env, ERR_JS_IS_NOT_SYSTEM_APP);
        return nullptr;
    }
    return InnerIsOsAccountConstraintEnable(env, cbInfo, true);
}

napi_value IsOsAccountUnlocked(napi_env env, napi_callback_info cbInfo)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    if (argc != 0 && AccountPermissionManager::CheckSystemApp(false) != ERR_OK) {
        AccountNapiThrow(env, ERR_JS_IS_NOT_SYSTEM_APP);
        return nullptr;
    }
    return InnerIsOsAccountVerified(env, cbInfo, true);
}

napi_value GetEnabledOsAccountConstraints(napi_env env, napi_callback_info cbInfo)
{
    if (AccountPermissionManager::CheckSystemApp(false) != ERR_OK) {
        AccountNapiThrow(env, ERR_JS_IS_NOT_SYSTEM_APP);
        return nullptr;
    }
    return GetOsAccountAllConstraintsInner(env, cbInfo, true);
}

napi_value QueryOsAccount(napi_env env, napi_callback_info cbInfo)
{
    if (AccountPermissionManager::CheckSystemApp(false) != ERR_OK) {
        AccountNapiThrow(env, ERR_JS_IS_NOT_SYSTEM_APP);
        return nullptr;
    }
    return QueryCurrentOsAccountInner(env, cbInfo, true);
}
}  // namespace AccountJsKit
}  // namespace OHOS