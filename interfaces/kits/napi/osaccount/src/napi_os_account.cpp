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

#include "napi_os_account.h"
#include "napi_account_error.h"
#include "napi_os_account_common.h"

using namespace OHOS::AccountSA;

namespace OHOS {
namespace AccountJsKit {
namespace {
const int OS_ACCOUNT_TYPE_ADMIN = 0;
const int OS_ACCOUNT_TYPE_NORMAL = 1;
const int OS_ACCOUNT_TYPE_GUEST = 2;
std::mutex g_lockForOsAccountSubscribers;
std::map<OsAccountManager *, std::vector<SubscribeCBInfo *>> g_osAccountSubscribers;
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

    napi_value constraintSourceType = nullptr;
    napi_create_object(env, &constraintSourceType);
    SetEnumProperty(env, constraintSourceType, CONSTRAINT_NOT_EXIST, "CONSTRAINT_NOT_EXIST");
    SetEnumProperty(env, constraintSourceType, CONSTRAINT_TYPE_BASE, "CONSTRAINT_TYPE_BASE");
    SetEnumProperty(env, constraintSourceType, CONSTRAINT_TYPE_DEVICE_OWNER, "CONSTRAINT_TYPE_DEVICE_OWNER");
    SetEnumProperty(env, constraintSourceType, CONSTRAINT_TYPE_PROFILE_OWNER, "CONSTRAINT_TYPE_PROFILE_OWNER");

    napi_property_descriptor exportEnum[] = {
        DECLARE_NAPI_PROPERTY("OsAccountType", osAccountType),
        DECLARE_NAPI_PROPERTY("ConstraintSourceType", constraintSourceType),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(exportEnum) / sizeof(*exportEnum), exportEnum));

    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("queryOsAccountById", QueryOsAccountById),
        DECLARE_NAPI_FUNCTION("removeOsAccount", RemoveOsAccount),
        DECLARE_NAPI_FUNCTION("setOsAccountName", SetOsAccountName),
        DECLARE_NAPI_FUNCTION("setOsAccountConstraints", SetOsAccountConstraints),
        DECLARE_NAPI_FUNCTION("activateOsAccount", ActivateOsAccount),
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
        DECLARE_NAPI_FUNCTION("getOsAccountProfilePhoto", GetOsAccountProfilePhoto),
        DECLARE_NAPI_FUNCTION("queryCurrentOsAccount", QueryCurrentOsAccount),
        DECLARE_NAPI_FUNCTION("getCurrentOsAccount", GetCurrentOsAccount),
        DECLARE_NAPI_FUNCTION("getOsAccountLocalIdFromUid", GetOsAccountLocalIdFromUid),
        DECLARE_NAPI_FUNCTION("queryOsAccountLocalIdFromUid", QueryOsAccountLocalIdFromUid),
        DECLARE_NAPI_FUNCTION("getOsAccountLocalIdForUid", QueryOsAccountLocalIdFromUid),
        DECLARE_NAPI_FUNCTION("getBundleIdFromUid", GetBundleIdFromUid),
        DECLARE_NAPI_FUNCTION("getBundleIdForUid", GetBundleIdFromUid),
        DECLARE_NAPI_FUNCTION("getOsAccountLocalIdFromDomain", GetOsAccountLocalIdFromDomain),
        DECLARE_NAPI_FUNCTION("queryOsAccountLocalIdFromDomain", QueryOsAccountLocalIdFromDomain),
        DECLARE_NAPI_FUNCTION("getOsAccountLocalIdForDomain", QueryOsAccountLocalIdFromDomain),
        DECLARE_NAPI_FUNCTION("setOsAccountProfilePhoto", SetOsAccountProfilePhoto),
        DECLARE_NAPI_FUNCTION("queryMaxOsAccountNumber", QueryMaxOsAccountNumber),
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
    };
    napi_value cons = nullptr;
    NAPI_CALL(env,
        napi_define_class(env,
            OS_ACCOUNT_CLASS_NAME.c_str(),
            OS_ACCOUNT_CLASS_NAME.size(),
            OsAccountJsConstructor,
            nullptr,
            sizeof(properties) / sizeof(napi_property_descriptor),
            properties,
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
    QueryOAByIdAsyncContext *queryOAByIdCB = new (std::nothrow) QueryOAByIdAsyncContext();
    if (queryOAByIdCB == nullptr) {
        ACCOUNT_LOGE("insufficient memory for queryOAByIdCB!");
        return WrapVoidToJS(env);
    }
    queryOAByIdCB->env = env;
    queryOAByIdCB->callbackRef = nullptr;
    queryOAByIdCB->throwErr = true;

    if (!ParseParaQueryOAByIdCB(env, cbInfo, queryOAByIdCB)) {
        delete queryOAByIdCB;
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
        reinterpret_cast<void *>(queryOAByIdCB),
        &queryOAByIdCB->work);

    napi_queue_async_work(env, queryOAByIdCB->work);
    return result;
}

napi_value RemoveOsAccount(napi_env env, napi_callback_info cbInfo)
{
    RemoveOAAsyncContext *removeOACB = new (std::nothrow) RemoveOAAsyncContext();
    if (removeOACB == nullptr) {
        ACCOUNT_LOGE("insufficient memory for removeOACB!");
        return WrapVoidToJS(env);
    }
    removeOACB->env = env;
    removeOACB->callbackRef = nullptr;
    removeOACB->throwErr = true;

    if (!ParseParaRemoveOACB(env, cbInfo, removeOACB)) {
        delete removeOACB;
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
        reinterpret_cast<void *>(removeOACB), &removeOACB->work);

    napi_queue_async_work(env, removeOACB->work);
    return result;
}

napi_value SetOsAccountName(napi_env env, napi_callback_info cbInfo)
{
    SetOANameAsyncContext *setOANameCB = new (std::nothrow) SetOANameAsyncContext();
    if (setOANameCB == nullptr) {
        ACCOUNT_LOGE("insufficient memory for setOANameCB!");
        return WrapVoidToJS(env);
    }
    setOANameCB->env = env;
    setOANameCB->callbackRef = nullptr;
    setOANameCB->throwErr = true;

    if (!ParseParaSetOAName(env, cbInfo, setOANameCB)) {
        delete setOANameCB;
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
        reinterpret_cast<void *>(setOANameCB),
        &setOANameCB->work);

    napi_queue_async_work(env, setOANameCB->work);
    return result;
}

napi_value SetOsAccountConstraints(napi_env env, napi_callback_info cbInfo)
{
    SetOAConsAsyncContext *setOAConsCB = new (std::nothrow) SetOAConsAsyncContext();
    if (setOAConsCB == nullptr) {
        ACCOUNT_LOGE("insufficient memory for setOAConsCB!");
        return WrapVoidToJS(env);
    }
    setOAConsCB->env = env;
    setOAConsCB->callbackRef = nullptr;
    setOAConsCB->throwErr = true;

    if (!ParseParaSetOAConstraints(env, cbInfo, setOAConsCB)) {
        delete setOAConsCB;
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
        reinterpret_cast<void *>(setOAConsCB),
        &setOAConsCB->work);

    napi_queue_async_work(env, setOAConsCB->work);
    return result;
}

napi_value ActivateOsAccount(napi_env env, napi_callback_info cbInfo)
{
    ActivateOAAsyncContext *activeOACB = new (std::nothrow) ActivateOAAsyncContext();
    if (activeOACB == nullptr) {
        ACCOUNT_LOGE("insufficient memory for activeOACB!");
        return WrapVoidToJS(env);
    }
    activeOACB->env = env;
    activeOACB->callbackRef = nullptr;
    activeOACB->throwErr = true;

    if (!ParseParaActiveOA(env, cbInfo, activeOACB)) {
        delete activeOACB;
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
        reinterpret_cast<void *>(activeOACB),
        &activeOACB->work);

    napi_queue_async_work(env, activeOACB->work);
    return result;
}

napi_value CreateOsAccount(napi_env env, napi_callback_info cbInfo)
{
    CreateOAAsyncContext *createOACB = new (std::nothrow) CreateOAAsyncContext();
    if (createOACB == nullptr) {
        ACCOUNT_LOGE("insufficient memory for createOACB!");
        return WrapVoidToJS(env);
    }
    createOACB->env = env;
    createOACB->callbackRef = nullptr;
    createOACB->throwErr = true;

    if (!ParseParaCreateOA(env, cbInfo, createOACB)) {
        delete createOACB;
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
        reinterpret_cast<void *>(createOACB), &createOACB->work);

    napi_queue_async_work(env, createOACB->work);
    return result;
}

napi_value CreateOsAccountForDomain(napi_env env, napi_callback_info cbInfo)
{
    CreateOAForDomainAsyncContext *createOAForDomainCB = new (std::nothrow) CreateOAForDomainAsyncContext();
    if (createOAForDomainCB == nullptr) {
        ACCOUNT_LOGE("insufficient memory for createOAForDomainCB!");
        return WrapVoidToJS(env);
    }
    createOAForDomainCB->env = env;
    createOAForDomainCB->callbackRef = nullptr;
    createOAForDomainCB->throwErr = true;

    if (!ParseParaCreateOAForDomain(env, cbInfo, createOAForDomainCB)) {
        delete createOAForDomainCB;
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

    napi_create_async_work(env, nullptr, resource, CreateOAForDomainExecuteCB, CreateOAForDomainCallbackCompletedCB,
        reinterpret_cast<void *>(createOAForDomainCB), &createOAForDomainCB->work);

    napi_queue_async_work(env, createOAForDomainCB->work);
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
    GetOACountAsyncContext *getOACount = new (std::nothrow) GetOACountAsyncContext();
    if (getOACount == nullptr) {
        ACCOUNT_LOGE("insufficient memory for getOACount!");
        return WrapVoidToJS(env);
    }
    getOACount->env = env;
    getOACount->callbackRef = nullptr;
    getOACount->throwErr = throwErr;

    if (!ParseParaGetOACount(env, cbInfo, getOACount) && throwErr) {
        delete getOACount;
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
        reinterpret_cast<void *>(getOACount),
        &getOACount->work);

    napi_queue_async_work(env, getOACount->work);
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
    DbDeviceIdAsyncContext *dbDeviceId = new (std::nothrow) DbDeviceIdAsyncContext();
    if (dbDeviceId == nullptr) {
        ACCOUNT_LOGE("insufficient memory for DbDeviceId!");
        return WrapVoidToJS(env);
    }
    dbDeviceId->env = env;
    dbDeviceId->callbackRef = nullptr;
    dbDeviceId->throwErr = throwErr;

    if (!ParseParaDbDeviceId(env, cbInfo, dbDeviceId) && throwErr) {
        delete dbDeviceId;
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
        reinterpret_cast<void *>(dbDeviceId),
        &dbDeviceId->work);

    napi_queue_async_work(env, dbDeviceId->work);
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
    GetAllConsAsyncContext *getAllConsCB = new (std::nothrow) GetAllConsAsyncContext();
    if (getAllConsCB == nullptr) {
        ACCOUNT_LOGE("insufficient memory for getAllConsCB!");
        return WrapVoidToJS(env);
    }
    getAllConsCB->env = env;
    getAllConsCB->callbackRef = nullptr;
    getAllConsCB->throwErr = throwErr;

    if (!ParseParaGetAllCons(env, cbInfo, getAllConsCB) && throwErr) {
        delete getAllConsCB;
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
        reinterpret_cast<void *>(getAllConsCB),
        &getAllConsCB->work);

    napi_queue_async_work(env, getAllConsCB->work);
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
    GetIdAsyncContext *getIdCB = new (std::nothrow) GetIdAsyncContext();
    if (getIdCB == nullptr) {
        ACCOUNT_LOGE("insufficient memory for getIdCB!");
        return WrapVoidToJS(env);
    }
    getIdCB->env = env;
    getIdCB->callbackRef = nullptr;
    getIdCB->throwErr = throwErr;

    if (!ParseParaProcessId(env, cbInfo, getIdCB) && throwErr) {
        delete getIdCB;
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
        reinterpret_cast<void *>(getIdCB),
        &getIdCB->work);

    napi_queue_async_work(env, getIdCB->work);
    return result;
}

napi_value QueryAllCreatedOsAccounts(napi_env env, napi_callback_info cbInfo)
{
    QueryCreateOAAsyncContext *queryAllOA = new (std::nothrow) QueryCreateOAAsyncContext();
    if (queryAllOA == nullptr) {
        ACCOUNT_LOGE("insufficient memory for queryAllOA!");
        return WrapVoidToJS(env);
    }
    queryAllOA->env = env;
    queryAllOA->callbackRef = nullptr;
    queryAllOA->throwErr = true;

    if (!ParseQueryAllCreateOA(env, cbInfo, queryAllOA)) {
        delete queryAllOA;
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
        reinterpret_cast<void *>(queryAllOA),
        &queryAllOA->work);

    napi_queue_async_work(env, queryAllOA->work);
    return result;
}

napi_value QueryOsAccountConstraintSourceTypes(napi_env env, napi_callback_info cbInfo)
{
    QueryOAConstraintSrcTypeContext *queryConstraintSource = new (std::nothrow) QueryOAConstraintSrcTypeContext();
    if (queryConstraintSource == nullptr) {
        ACCOUNT_LOGE("queryConstraintSource == nullptr");
        return WrapVoidToJS(env);
    }
    queryConstraintSource->env = env;
    queryConstraintSource->callbackRef = nullptr;
    queryConstraintSource->throwErr = true;

    if (!ParseQueryOAConstraintSrcTypes(env, cbInfo, queryConstraintSource)) {
        delete queryConstraintSource;
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
        reinterpret_cast<void *>(queryConstraintSource),
        &queryConstraintSource->work);

    napi_queue_async_work(env, queryConstraintSource->work);
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
    QueryActiveIdsAsyncContext *queryActiveIds = new (std::nothrow) QueryActiveIdsAsyncContext();
    if (queryActiveIds == nullptr) {
        ACCOUNT_LOGE("insufficient memory for queryActiveIds!");
        return WrapVoidToJS(env);
    }
    queryActiveIds->env = env;
    queryActiveIds->callbackRef = nullptr;
    queryActiveIds->throwErr = throwErr;

    if (!ParseQueryActiveIds(env, cbInfo, queryActiveIds) && throwErr) {
        delete queryActiveIds;
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
        reinterpret_cast<void *>(queryActiveIds),
        &queryActiveIds->work);

    napi_queue_async_work(env, queryActiveIds->work);
    return result;
}

napi_value GetOsAccountProfilePhoto(napi_env env, napi_callback_info cbInfo)
{
    GetOAPhotoAsyncContext *getPhoto = new (std::nothrow) GetOAPhotoAsyncContext();
    if (getPhoto == nullptr) {
        ACCOUNT_LOGE("insufficient memory for queryAllOA!");
        return WrapVoidToJS(env);
    }
    getPhoto->env = env;
    getPhoto->callbackRef = nullptr;
    getPhoto->throwErr = true;

    if (!ParseParaGetPhoto(env, cbInfo, getPhoto)) {
        delete getPhoto;
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
        reinterpret_cast<void *>(getPhoto), &getPhoto->work);

    napi_queue_async_work(env, getPhoto->work);
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
    CurrentOAAsyncContext *currentOA = new (std::nothrow) CurrentOAAsyncContext();
    if (currentOA == nullptr) {
        ACCOUNT_LOGE("insufficient memory for currentOA!");
        return WrapVoidToJS(env);
    }
    currentOA->env = env;
    currentOA->callbackRef = nullptr;
    currentOA->throwErr = throwErr;

    if (!ParseParaCurrentOA(env, cbInfo, currentOA) && throwErr) {
        delete currentOA;
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
        reinterpret_cast<void *>(currentOA),
        &currentOA->work);

    napi_queue_async_work(env, currentOA->work);
    return result;
}

napi_value QueryOsAccountLocalIdFromUid(napi_env env, napi_callback_info cbInfo)
{
    return GetOsAccountLocalIdFromUidInner(env, cbInfo, true);
}

napi_value GetOsAccountLocalIdFromUid(napi_env env, napi_callback_info cbInfo)
{
    return GetOsAccountLocalIdFromUidInner(env, cbInfo, false);
}

napi_value GetOsAccountLocalIdFromUidInner(napi_env env, napi_callback_info cbInfo, bool throwErr)
{
    GetIdByUidAsyncContext *idByUid = new (std::nothrow) GetIdByUidAsyncContext();
    if (idByUid == nullptr) {
        ACCOUNT_LOGE("insufficient memory for idByUid!");
        return WrapVoidToJS(env);
    }
    idByUid->env = env;
    idByUid->callbackRef = nullptr;
    idByUid->throwErr = throwErr;

    if (!ParseParaGetIdByUid(env, cbInfo, idByUid) && throwErr) {
        delete idByUid;
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
        reinterpret_cast<void *>(idByUid), &idByUid->work);

    napi_queue_async_work(env, idByUid->work);
    return result;
}

napi_value GetBundleIdFromUid(napi_env env, napi_callback_info cbInfo)
{
    GetIdByUidAsyncContext *bundleIdByUid = new (std::nothrow) GetIdByUidAsyncContext();
    if (bundleIdByUid == nullptr) {
        ACCOUNT_LOGE("insufficient memory for bundleIdByUid!");
        return WrapVoidToJS(env);
    }
    bundleIdByUid->env = env;
    bundleIdByUid->callbackRef = nullptr;
    bundleIdByUid->throwErr = true;

    if (!ParseParaGetIdByUid(env, cbInfo, bundleIdByUid)) {
        delete bundleIdByUid;
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
        reinterpret_cast<void *>(bundleIdByUid),
        &bundleIdByUid->work);

    napi_queue_async_work(env, bundleIdByUid->work);
    return result;
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
    GetIdByDomainAsyncContext *idByDomain = new (std::nothrow) GetIdByDomainAsyncContext();
    if (idByDomain == nullptr) {
        ACCOUNT_LOGE("insufficient memory for idByDomain!");
        return WrapVoidToJS(env);
    }
    idByDomain->env = env;
    idByDomain->callbackRef = nullptr;
    idByDomain->throwErr = throwErr;

    if (!ParseParaGetIdByDomain(env, cbInfo, idByDomain) && throwErr) {
        delete idByDomain;
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
        reinterpret_cast<void *>(idByDomain), &idByDomain->work);

    napi_queue_async_work(env, idByDomain->work);
    return result;
}

napi_value SetOsAccountProfilePhoto(napi_env env, napi_callback_info cbInfo)
{
    SetOAPhotoAsyncContext *setPhoto = new (std::nothrow) SetOAPhotoAsyncContext();
    if (setPhoto == nullptr) {
        ACCOUNT_LOGE("insufficient memory for setPhoto!");
        return WrapVoidToJS(env);
    }
    setPhoto->env = env;
    setPhoto->callbackRef = nullptr;
    setPhoto->throwErr = true;

    if (!ParseParaSetPhoto(env, cbInfo, setPhoto)) {
        delete setPhoto;
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
        reinterpret_cast<void *>(setPhoto), &setPhoto->work);

    napi_queue_async_work(env, setPhoto->work);
    return result;
}

napi_value QueryMaxOsAccountNumber(napi_env env, napi_callback_info cbInfo)
{
    QueryMaxNumAsyncContext *maxNum = new (std::nothrow) QueryMaxNumAsyncContext();
    if (maxNum == nullptr) {
        ACCOUNT_LOGE("insufficient memory for maxNum!");
        return WrapVoidToJS(env);
    }
    maxNum->env = env;
    maxNum->callbackRef = nullptr;
    maxNum->throwErr = true;

    if (!ParseParaQueryMaxNum(env, cbInfo, maxNum)) {
        delete maxNum;
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
        reinterpret_cast<void *>(maxNum), &maxNum->work);

    napi_queue_async_work(env, maxNum->work);
    return result;
}

napi_value InnerIsOsAccountActived(napi_env env, napi_callback_info cbInfo, bool throwErr)
{
    IsActivedAsyncContext *isActived = new (std::nothrow) IsActivedAsyncContext();
    if (isActived == nullptr) {
        ACCOUNT_LOGE("insufficient memory for isActived!");
        return WrapVoidToJS(env);
    }
    isActived->env = env;
    isActived->callbackRef = nullptr;
    isActived->throwErr = throwErr;

    if (!ParseParaIsActived(env, cbInfo, isActived) && throwErr) {
        delete isActived;
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
        reinterpret_cast<void *>(isActived), &isActived->work);

    napi_queue_async_work(env, isActived->work);
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
    IsConEnableAsyncContext *isEnable = new (std::nothrow) IsConEnableAsyncContext();
    if (isEnable == nullptr) {
        ACCOUNT_LOGE("insufficient memory for isEnable!");
        return WrapVoidToJS(env);
    }
    isEnable->env = env;
    isEnable->callbackRef = nullptr;
    isEnable->throwErr = throwErr;

    if (!ParseParaIsEnable(env, cbInfo, isEnable) && throwErr) {
        delete isEnable;
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
        reinterpret_cast<void *>(isEnable), &isEnable->work);

    napi_queue_async_work(env, isEnable->work);
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
    GetTypeAsyncContext *getType = new (std::nothrow) GetTypeAsyncContext();
    if (getType == nullptr) {
        ACCOUNT_LOGE("insufficient memory for getType!");
        return WrapVoidToJS(env);
    }
    getType->env = env;
    getType->callbackRef = nullptr;
    getType->throwErr = throwErr;

    if (!ParseParaGetType(env, cbInfo, getType) && throwErr) {
        delete getType;
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
        reinterpret_cast<void *>(getType), &getType->work);

    napi_queue_async_work(env, getType->work);
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
    IsMultiEnAsyncContext *multiEn = new (std::nothrow) IsMultiEnAsyncContext();
    if (multiEn == nullptr) {
        ACCOUNT_LOGE("insufficient memory for multiEn!");
        return WrapVoidToJS(env);
    }
    multiEn->env = env;
    multiEn->callbackRef = nullptr;
    multiEn->throwErr = throwErr;

    if (!ParseParaIsMultiEn(env, cbInfo, multiEn) && throwErr) {
        delete multiEn;
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
        reinterpret_cast<void *>(multiEn), &multiEn->work);

    napi_queue_async_work(env, multiEn->work);
    return result;
}

napi_value InnerIsOsAccountVerified(napi_env env, napi_callback_info cbInfo, bool throwErr)
{
    IsVerifiedAsyncContext *isVerified = new (std::nothrow) IsVerifiedAsyncContext();
    if (isVerified == nullptr) {
        ACCOUNT_LOGE("insufficient memory for isVerified!");
        return WrapVoidToJS(env);
    }
    isVerified->env = env;
    isVerified->callbackRef = nullptr;
    isVerified->throwErr = throwErr;

    if (!ParseParaIsVerified(env, cbInfo, isVerified) && throwErr) {
        delete isVerified;
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
        reinterpret_cast<void *>(isVerified), &isVerified->work);

    napi_queue_async_work(env, isVerified->work);
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
    GetSerialNumIdCBInfo *serialNumId = new (std::nothrow) GetSerialNumIdCBInfo();
    if (serialNumId == nullptr) {
        ACCOUNT_LOGE("insufficient memory for serialNumId!");
        return WrapVoidToJS(env);
    }
    serialNumId->env = env;
    serialNumId->callbackRef = nullptr;
    serialNumId->throwErr = throwErr;

    if (!ParseParaSerialNumId(env, cbInfo, serialNumId) && throwErr) {
        delete serialNumId;
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
        reinterpret_cast<void *>(serialNumId), &serialNumId->work);

    napi_queue_async_work(env, serialNumId->work);
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
    GetSerialNumForOAInfo *getSerialNum = new (std::nothrow) GetSerialNumForOAInfo();
    if (getSerialNum == nullptr) {
        ACCOUNT_LOGE("insufficient memory for getSerialNum!");
        return WrapVoidToJS(env);
    }
    getSerialNum->env = env;
    getSerialNum->callbackRef = nullptr;
    getSerialNum->throwErr = throwErr;

    if (!ParseParaGetSerialNum(env, cbInfo, getSerialNum) && throwErr) {
        delete getSerialNum;
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
        reinterpret_cast<void *>(getSerialNum),
        &getSerialNum->work);

    napi_queue_async_work(env, getSerialNum->work);
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
    IsTestOAInfo *isTest = new (std::nothrow) IsTestOAInfo();
    if (isTest == nullptr) {
        ACCOUNT_LOGE("insufficient memory for isTest!");
        return WrapVoidToJS(env);
    }
    isTest->env = env;
    isTest->callbackRef = nullptr;
    isTest->throwErr = throwErr;

    if (!ParseParaIsTestOA(env, cbInfo, isTest) && throwErr) {
        delete isTest;
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
            napi_delete_async_work(env, isTest->work);
            delete isTest;
            isTest = nullptr;
        },
        reinterpret_cast<void *>(isTest),
        &isTest->work);

    napi_queue_async_work(env, isTest->work);
    return result;
}

napi_value IsMainOsAccount(napi_env env, napi_callback_info cbInfo)
{
    IsMainOAInfo *isMain = new (std::nothrow) IsMainOAInfo();
    if (isMain == nullptr) {
        ACCOUNT_LOGE("insufficient memory for isMain!");
        return WrapVoidToJS(env);
    }
    isMain->env = env;
    isMain->callbackRef = nullptr;
    isMain->throwErr = true;

    if (!ParseParaIsMainOA(env, cbInfo, isMain)) {
        delete isMain;
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
            napi_delete_async_work(env, isMain->work);
            delete isMain;
            isMain = nullptr;
        },
        reinterpret_cast<void *>(isMain),
        &isMain->work);

    napi_queue_async_work(env, isMain->work);
    return result;
}

napi_value Subscribe(napi_env env, napi_callback_info cbInfo)
{
    SubscribeCBInfo *subscribeCBInfo = new (std::nothrow) SubscribeCBInfo();
    if (subscribeCBInfo == nullptr) {
        ACCOUNT_LOGE("insufficient memory for subscribeCBInfo!");
        return nullptr;
    }
    subscribeCBInfo->env = env;
    subscribeCBInfo->callbackRef = nullptr;
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

    {
        std::lock_guard<std::mutex> lock(g_lockForOsAccountSubscribers);
        g_osAccountSubscribers[objectInfo].emplace_back(subscribeCBInfo);
    }

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "Subscribe", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(env,
        nullptr,
        resourceName,
        SubscribeExecuteCB,
        SubscribeCompletedCB,
        reinterpret_cast<void *>(subscribeCBInfo),
        &subscribeCBInfo->work);
    napi_queue_async_work(env, subscribeCBInfo->work);
    return WrapVoidToJS(env);
}

SubscriberPtr::SubscriberPtr(const OsAccountSubscribeInfo &subscribeInfo) : OsAccountSubscriber(subscribeInfo)
{}

SubscriberPtr::~SubscriberPtr()
{}

void SubscriberPtr::OnAccountsChanged(const int &id_)
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

    subscriberOAWorker->id = id_;
    subscriberOAWorker->env = env_;
    subscriberOAWorker->ref = ref_;
    subscriberOAWorker->subscriber = this;
    work->data = reinterpret_cast<void *>(subscriberOAWorker);
    uv_queue_work(loop, work, [](uv_work_t *work) {}, UvQueueWorkOnAccountsChanged);
}

void UvQueueWorkOnAccountsChanged(uv_work_t *work, int status)
{
    if (work == nullptr || work->data == nullptr) {
        return;
    }
    SubscriberOAWorker *subscriberOAWorkerData = reinterpret_cast<SubscriberOAWorker *>(work->data);
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
        napi_value result[ARGS_SIZE_ONE] = {nullptr};
        napi_create_int32(subscriberOAWorkerData->env, subscriberOAWorkerData->id, &result[PARAMZERO]);
        napi_value undefined = nullptr;
        napi_get_undefined(subscriberOAWorkerData->env, &undefined);
        napi_value callback = nullptr;
        napi_get_reference_value(subscriberOAWorkerData->env, subscriberOAWorkerData->ref, &callback);
        napi_value resultOut = nullptr;
        napi_call_function(
            subscriberOAWorkerData->env, undefined, callback, ARGS_SIZE_ONE, &result[0], &resultOut);
    }
    delete subscriberOAWorkerData;
    subscriberOAWorkerData = nullptr;
    delete work;
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
    UnsubscribeCBInfo *unsubscribeCBInfo = new (std::nothrow) UnsubscribeCBInfo();
    if (unsubscribeCBInfo == nullptr) {
        ACCOUNT_LOGE("insufficient memory for unsubscribeCBInfo!");
        return WrapVoidToJS(env);
    }
    unsubscribeCBInfo->env = env;
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

    bool isFind = false;
    std::vector<std::shared_ptr<SubscriberPtr>> subscribers;
    FindSubscriberInMap(subscribers, unsubscribeCBInfo, isFind);
    if (!isFind) {
        ACCOUNT_LOGE("Unsubscribe failed. The current subscriber does not exist");
        return WrapVoidToJS(env);
    }
    unsubscribeCBInfo->subscribers = subscribers;

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "Unsubscribe", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(env,
        nullptr,
        resourceName,
        UnsubscribeExecuteCB,
        UnsubscribeCallbackCompletedCB,
        reinterpret_cast<void *>(unsubscribeCBInfo),
        &unsubscribeCBInfo->work);
    napi_queue_async_work(env, unsubscribeCBInfo->work);
    return WrapVoidToJS(env);
}

void FindSubscriberInMap(
    std::vector<std::shared_ptr<SubscriberPtr>> &subscribers, UnsubscribeCBInfo *unsubscribeCBInfo, bool &isFind)
{
    std::lock_guard<std::mutex> lock(g_lockForOsAccountSubscribers);

    for (auto subscriberInstance : g_osAccountSubscribers) {
        if (subscriberInstance.first == unsubscribeCBInfo->osManager) {
            for (auto item : subscriberInstance.second) {
                OsAccountSubscribeInfo subscribeInfo;
                OS_ACCOUNT_SUBSCRIBE_TYPE osSubscribeType;
                std::string name;
                item->subscriber->GetSubscribeInfo(subscribeInfo);
                subscribeInfo.GetOsAccountSubscribeType(osSubscribeType);
                subscribeInfo.GetName(name);
                if (unsubscribeCBInfo->osSubscribeType == osSubscribeType && unsubscribeCBInfo->name == name) {
                    subscribers.emplace_back(item->subscriber);
                }
            }
            if (subscribers.size() > 0) {
                isFind = true;
                break;
            }
        }
    }
}

void UnsubscribeExecuteCB(napi_env env, void *data)
{
    UnsubscribeCBInfo *unsubscribeCBInfo = reinterpret_cast<UnsubscribeCBInfo *>(data);
    ACCOUNT_LOGI("UnsubscribeExecuteCB Off size = %{public}zu", unsubscribeCBInfo->subscribers.size());
    for (auto offSubscriber : unsubscribeCBInfo->subscribers) {
        int errCode = OsAccountManager::UnsubscribeOsAccount(offSubscriber);
        ACCOUNT_LOGD("error code is %{public}d", errCode);
    }
}

void UnsubscribeCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGD("napi_create_async_work complete.");
    UnsubscribeCBInfo *unsubscribeCBInfo = reinterpret_cast<UnsubscribeCBInfo *>(data);
    if (unsubscribeCBInfo == nullptr) {
        return;
    }

    if (unsubscribeCBInfo->callbackRef != nullptr) {
        napi_value result = nullptr;
        napi_create_int32(env, 0, &result);

        napi_value undefined = nullptr;
        napi_get_undefined(env, &undefined);

        napi_value callback = nullptr;
        napi_value resultout = nullptr;
        napi_get_reference_value(env, unsubscribeCBInfo->callbackRef, &callback);

        napi_value results[ARGS_SIZE_ONE] = {nullptr};
        results[PARAMZERO] = result;

        NAPI_CALL_RETURN_VOID(
            env, napi_call_function(env, undefined, callback, ARGS_SIZE_ONE, &results[0], &resultout));

        napi_delete_reference(env, unsubscribeCBInfo->callbackRef);
    }

    napi_delete_async_work(env, unsubscribeCBInfo->work);

    // erase the info from map
    {
        std::lock_guard<std::mutex> lock(g_lockForOsAccountSubscribers);
        auto subscribe = g_osAccountSubscribers.find(unsubscribeCBInfo->osManager);
        if (subscribe != g_osAccountSubscribers.end()) {
            auto it = subscribe->second.begin();
            while (it != subscribe->second.end()) {
                if ((*it)->name == unsubscribeCBInfo->name &&
                    (*it)->osSubscribeType == unsubscribeCBInfo->osSubscribeType) {
                    napi_delete_reference(env, (*it)->callbackRef);
                    it = subscribe->second.erase(it);
                } else {
                    ++it;
                }
            }

            if (subscribe->second.size() == 0) {
                g_osAccountSubscribers.erase(subscribe);
            }
        }
    }

    delete unsubscribeCBInfo;
    unsubscribeCBInfo = nullptr;
}
}  // namespace AccountJsKit
}  // namespace OHOS
