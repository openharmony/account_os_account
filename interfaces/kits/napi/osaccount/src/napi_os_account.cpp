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
    ACCOUNT_LOGI("enter");
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

    napi_property_descriptor exportEnum[] = {
        DECLARE_NAPI_PROPERTY("OsAccountType", osAccountType),
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
        DECLARE_NAPI_FUNCTION("getDistributedVirtualDeviceId", GetDistributedVirtualDeviceId),
        DECLARE_NAPI_FUNCTION("getOsAccountAllConstraints", GetOsAccountAllConstraints),
        DECLARE_NAPI_FUNCTION("getOsAccountLocalIdFromProcess", GetOsAccountLocalIdFromProcess),
        DECLARE_NAPI_FUNCTION("queryAllCreatedOsAccounts", QueryAllCreatedOsAccounts),
        DECLARE_NAPI_FUNCTION("queryActivatedOsAccountIds", QueryActivatedOsAccountIds),
        DECLARE_NAPI_FUNCTION("getOsAccountProfilePhoto", GetOsAccountProfilePhoto),
        DECLARE_NAPI_FUNCTION("queryCurrentOsAccount", QueryCurrentOsAccount),
        DECLARE_NAPI_FUNCTION("getOsAccountLocalIdFromUid", GetOsAccountLocalIdFromUid),
        DECLARE_NAPI_FUNCTION("getBundleIdFromUid", GetBundleIdFromUid),
        DECLARE_NAPI_FUNCTION("getOsAccountLocalIdFromDomain", GetOsAccountLocalIdFromDomain),
        DECLARE_NAPI_FUNCTION("setOsAccountProfilePhoto", SetOsAccountProfilePhoto),
        DECLARE_NAPI_FUNCTION("queryMaxOsAccountNumber", QueryMaxOsAccountNumber),
        DECLARE_NAPI_FUNCTION("isOsAccountActived", IsOsAccountActived),
        DECLARE_NAPI_FUNCTION("isOsAccountConstraintEnable", IsOsAccountConstraintEnable),
        DECLARE_NAPI_FUNCTION("getOsAccountTypeFromProcess", GetOsAccountTypeFromProcess),
        DECLARE_NAPI_FUNCTION("isMultiOsAccountEnable", IsMultiOsAccountEnable),
        DECLARE_NAPI_FUNCTION("isOsAccountVerified", IsOsAccountVerified),
        DECLARE_NAPI_FUNCTION("getOsAccountLocalIdBySerialNumber", GetOsAccountLocalIdBySerialNumber),
        DECLARE_NAPI_FUNCTION("getSerialNumberByOsAccountLocalId", GetSerialNumberByOsAccountLocalId),
        DECLARE_NAPI_FUNCTION("isTestOsAccount", IsTestOsAccount),
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
    ACCOUNT_LOGI("enter");
    napi_value instance = nullptr;
    napi_value cons = nullptr;
    if (napi_get_reference_value(env, osAccountRef_, &cons) != napi_ok) {
        return nullptr;
    }
    ACCOUNT_LOGI("Get a reference to the global variable osAccountRef_ complete");
    if (napi_new_instance(env, cons, 0, nullptr, &instance) != napi_ok) {
        return nullptr;
    }

    return instance;
}

napi_value OsAccountJsConstructor(napi_env env, napi_callback_info cbinfo)
{
    ACCOUNT_LOGI("enter");
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, nullptr));

    OsAccountManager *objectInfo = new (std::nothrow) OsAccountManager();
    if (objectInfo == nullptr) {
        ACCOUNT_LOGI("objectInfo == nullptr");
        return WrapVoidToJS(env);
    }
    napi_wrap(env, thisVar, objectInfo, [](napi_env env, void *data, void *hint) {
        OsAccountManager *objInfo = (OsAccountManager *)data;
        delete objInfo;
    }, nullptr, nullptr);
    ACCOUNT_LOGI("OsAccountManager objectInfo at JsConstructor = %{public}p", objectInfo);

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
    ACCOUNT_LOGI("enter");
    QueryOAByIdAsyncContext *queryOAByIdCB = new (std::nothrow) QueryOAByIdAsyncContext();
    if (queryOAByIdCB == nullptr) {
        ACCOUNT_LOGI("queryOAByIdCB == nullptr");
        return WrapVoidToJS(env);
    }
    queryOAByIdCB->env = env;
    queryOAByIdCB->callbackRef = nullptr;

    if (ParseParaQueryOAByIdCB(env, cbInfo, queryOAByIdCB) == nullptr) {
        ACCOUNT_LOGI("Parse query by id failed");
        delete queryOAByIdCB;
        return WrapVoidToJS(env);
    }
    ACCOUNT_LOGI("Parse completed, id = %{public}d", queryOAByIdCB->id);

    napi_value result = nullptr;
    if (queryOAByIdCB->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        napi_create_promise(env, &queryOAByIdCB->deferred, &result);
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
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
    ACCOUNT_LOGI("enter");
    RemoveOAAsyncContext *removeOACB = new (std::nothrow) RemoveOAAsyncContext();
    if (removeOACB == nullptr) {
        ACCOUNT_LOGI("removeOACB == nullptr");
        return WrapVoidToJS(env);
    }
    removeOACB->env = env;
    removeOACB->callbackRef = nullptr;

    if (ParseParaRemoveOACB(env, cbInfo, removeOACB) == nullptr) {
        ACCOUNT_LOGI("Parse remove osaccount failed");
        delete removeOACB;
        return WrapVoidToJS(env);
    }
    ACCOUNT_LOGI("Parse completed, id = %{public}d", removeOACB->id);

    napi_value result = nullptr;
    if (removeOACB->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        napi_create_promise(env, &removeOACB->deferred, &result);
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
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
    ACCOUNT_LOGI("enter");
    SetOANameAsyncContext *setOANameCB = new (std::nothrow) SetOANameAsyncContext();
    if (setOANameCB == nullptr) {
        ACCOUNT_LOGI("setOANameCB == nullptr");
        return WrapVoidToJS(env);
    }
    setOANameCB->env = env;
    setOANameCB->callbackRef = nullptr;

    if (ParseParaSetOAName(env, cbInfo, setOANameCB) == nullptr) {
        ACCOUNT_LOGI("Parse set osaccount name failed");
        delete setOANameCB;
        return WrapVoidToJS(env);
    }
    ACCOUNT_LOGI("Parse completed, id = %{public}d, name = %{public}s", setOANameCB->id, setOANameCB->name.c_str());

    napi_value result = nullptr;
    if (setOANameCB->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        napi_create_promise(env, &setOANameCB->deferred, &result);
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
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
    ACCOUNT_LOGI("enter");
    SetOAConsAsyncContext *setOAConsCB = new (std::nothrow) SetOAConsAsyncContext();
    if (setOAConsCB == nullptr) {
        ACCOUNT_LOGI("setOAConsCB == nullptr");
        return WrapVoidToJS(env);
    }
    setOAConsCB->env = env;
    setOAConsCB->callbackRef = nullptr;

    if (ParseParaSetOAConstraints(env, cbInfo, setOAConsCB) == nullptr) {
        ACCOUNT_LOGI("Parse set constraints failed");
        delete setOAConsCB;
        return WrapVoidToJS(env);
    }
    ACCOUNT_LOGI("Parse completed, id = %{public}d", setOAConsCB->id);

    napi_value result = nullptr;
    if (setOAConsCB->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        napi_create_promise(env, &setOAConsCB->deferred, &result);
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
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
    ACCOUNT_LOGI("enter");
    ActivateOAAsyncContext *activeOACB = new (std::nothrow) ActivateOAAsyncContext();
    if (activeOACB == nullptr) {
        ACCOUNT_LOGI("activeOACB == nullptr");
        return WrapVoidToJS(env);
    }
    activeOACB->env = env;
    activeOACB->callbackRef = nullptr;

    if (ParseParaActiveOA(env, cbInfo, activeOACB) == nullptr) {
        ACCOUNT_LOGI("Parse activite faile");
        delete activeOACB;
        return WrapVoidToJS(env);
    }
    ACCOUNT_LOGI("Parse completed, id = %{public}d", activeOACB->id);

    napi_value result = nullptr;
    if (activeOACB->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        napi_create_promise(env, &activeOACB->deferred, &result);
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
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
    ACCOUNT_LOGI("enter");
    CreateOAAsyncContext *createOACB = new (std::nothrow) CreateOAAsyncContext();
    if (createOACB == nullptr) {
        ACCOUNT_LOGI("createOACB == nullptr");
        return WrapVoidToJS(env);
    }
    createOACB->env = env;
    createOACB->callbackRef = nullptr;

    if (ParseParaCreateOA(env, cbInfo, createOACB) == nullptr) {
        ACCOUNT_LOGI("Parse create osaccount failed");
        delete createOACB;
        return WrapVoidToJS(env);
    }
    ACCOUNT_LOGI("Parse completed, type = %{publilc}d, name = %{public}s", createOACB->type, createOACB->name.c_str());

    napi_value result = nullptr;
    if (createOACB->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        napi_create_promise(env, &createOACB->deferred, &result);
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
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
    ACCOUNT_LOGI("enter");
    CreateOAForDomainAsyncContext *createOAForDomainCB = new (std::nothrow) CreateOAForDomainAsyncContext();
    if (createOAForDomainCB == nullptr) {
        ACCOUNT_LOGI("createOAForDomainCB == nullptr");
        return WrapVoidToJS(env);
    }
    createOAForDomainCB->env = env;
    createOAForDomainCB->callbackRef = nullptr;

    if (ParseParaCreateOAForDomain(env, cbInfo, createOAForDomainCB) == nullptr) {
        ACCOUNT_LOGI("Parse create osaccount failed");
        delete createOAForDomainCB;
        return WrapVoidToJS(env);
    }

    napi_value result = nullptr;
    if (createOAForDomainCB->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        napi_create_promise(env, &createOAForDomainCB->deferred, &result);
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "CreateOsAccountForDomain", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env, nullptr, resource, CreateOAForDomainExecuteCB, CreateOAForDomainCallbackCompletedCB,
        reinterpret_cast<void *>(createOAForDomainCB), &createOAForDomainCB->work);

    napi_queue_async_work(env, createOAForDomainCB->work);
    return result;
}

napi_value GetCreatedOsAccountsCount(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("enter");
    GetOACountAsyncContext *getOACount = new (std::nothrow) GetOACountAsyncContext();
    if (getOACount == nullptr) {
        ACCOUNT_LOGI("getOACount == nullptr");
        return WrapVoidToJS(env);
    }
    getOACount->env = env;
    getOACount->callbackRef = nullptr;

    ParseParaGetOACount(env, cbInfo, getOACount);

    napi_value result = nullptr;
    if (getOACount->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        napi_create_promise(env, &getOACount->deferred, &result);
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "GetCreatedOsAccountsCount", NAPI_AUTO_LENGTH, &resource);

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

napi_value GetDistributedVirtualDeviceId(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("enter");
    DbDeviceIdAsyncContext *dbDeviceId = new (std::nothrow) DbDeviceIdAsyncContext();
    if (dbDeviceId == nullptr) {
        ACCOUNT_LOGI("DbDeviceId == nullptr");
        return WrapVoidToJS(env);
    }
    dbDeviceId->env = env;
    dbDeviceId->callbackRef = nullptr;

    ParseParaDbDeviceId(env, cbInfo, dbDeviceId);

    napi_value result = nullptr;
    if (dbDeviceId->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        napi_create_promise(env, &dbDeviceId->deferred, &result);
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "GetDistributedVirtualDeviceId", NAPI_AUTO_LENGTH, &resource);

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

napi_value GetOsAccountAllConstraints(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("enter");
    GetAllConsAsyncContext *getAllConsCB = new (std::nothrow) GetAllConsAsyncContext();
    if (getAllConsCB == nullptr) {
        ACCOUNT_LOGI("getAllConsCB == nullptr");
        return WrapVoidToJS(env);
    }
    getAllConsCB->env = env;
    getAllConsCB->callbackRef = nullptr;

    if (ParseParaGetAllCons(env, cbInfo, getAllConsCB) == nullptr) {
        ACCOUNT_LOGI("Parse get all constraints failed");
        delete getAllConsCB;
        return WrapVoidToJS(env);
    }

    napi_value result = nullptr;
    if (getAllConsCB->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        napi_create_promise(env, &getAllConsCB->deferred, &result);
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
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

napi_value GetOsAccountLocalIdFromProcess(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("enter");
    GetIdAsyncContext *getIdCB = new (std::nothrow) GetIdAsyncContext();
    if (getIdCB == nullptr) {
        ACCOUNT_LOGI("getIdCB == nullptr");
        return WrapVoidToJS(env);
    }
    getIdCB->env = env;
    getIdCB->callbackRef = nullptr;

    ParseParaProcessId(env, cbInfo, getIdCB);

    napi_value result = nullptr;
    if (getIdCB->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        napi_create_promise(env, &getIdCB->deferred, &result);
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "GetOsAccountLocalIdFromProcess", NAPI_AUTO_LENGTH, &resource);

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
    ACCOUNT_LOGI("enter");
    QueryCreateOAAsyncContext *queryAllOA = new (std::nothrow) QueryCreateOAAsyncContext();
    if (queryAllOA == nullptr) {
        ACCOUNT_LOGI("queryAllOA == nullptr");
        return WrapVoidToJS(env);
    }
    queryAllOA->env = env;
    queryAllOA->callbackRef = nullptr;

    ParseQueryAllCreateOA(env, cbInfo, queryAllOA);

    napi_value result = nullptr;
    if (queryAllOA->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        napi_create_promise(env, &queryAllOA->deferred, &result);
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
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

napi_value QueryActivatedOsAccountIds(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("enter");
    QueryActiveIdsAsyncContext *queryActiveIds = new (std::nothrow) QueryActiveIdsAsyncContext();
    if (queryActiveIds == nullptr) {
        ACCOUNT_LOGI("queryActiveIds == nullptr");
        return WrapVoidToJS(env);
    }
    queryActiveIds->env = env;
    queryActiveIds->callbackRef = nullptr;

    ParseQueryActiveIds(env, cbInfo, queryActiveIds);

    napi_value result = nullptr;
    if (queryActiveIds->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        napi_create_promise(env, &queryActiveIds->deferred, &result);
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "QueryActivatedOsAccountIds", NAPI_AUTO_LENGTH, &resource);

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
    ACCOUNT_LOGI("enter");
    GetOAPhotoAsyncContext *getPhoto = new (std::nothrow) GetOAPhotoAsyncContext();
    if (getPhoto == nullptr) {
        ACCOUNT_LOGI("queryAllOA == nullptr");
        return WrapVoidToJS(env);
    }
    getPhoto->env = env;
    getPhoto->callbackRef = nullptr;

    if (ParseParaGetPhote(env, cbInfo, getPhoto) == nullptr) {
        ACCOUNT_LOGI("Parse get osaccount profile photo failed");
        delete getPhoto;
        return WrapVoidToJS(env);
    }
    ACCOUNT_LOGI("Parse completed, id = %{public}d", getPhoto->id);

    napi_value result = nullptr;
    if (getPhoto->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        napi_create_promise(env, &getPhoto->deferred, &result);
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "GetOsAccountProfilePhoto", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env, nullptr, resource, GetOAPhoteExecuteCB, GetOAPhoteCallbackCompletedCB,
        reinterpret_cast<void *>(getPhoto), &getPhoto->work);

    napi_queue_async_work(env, getPhoto->work);
    return result;
}

napi_value QueryCurrentOsAccount(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("enter");
    CurrentOAAsyncContext *currentOA = new (std::nothrow) CurrentOAAsyncContext();
    if (currentOA == nullptr) {
        ACCOUNT_LOGI("currentOA == nullptr");
        return WrapVoidToJS(env);
    }
    currentOA->env = env;
    currentOA->callbackRef = nullptr;

    ParseParaCurrentOA(env, cbInfo, currentOA);

    napi_value result = nullptr;
    if (currentOA->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        napi_create_promise(env, &currentOA->deferred, &result);
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
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

napi_value GetOsAccountLocalIdFromUid(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("enter");
    GetIdByUidAsyncContext *idByUid = new (std::nothrow) GetIdByUidAsyncContext();
    if (idByUid == nullptr) {
        ACCOUNT_LOGI("idByUid == nullptr");
        return WrapVoidToJS(env);
    }
    idByUid->env = env;
    idByUid->callbackRef = nullptr;

    if (ParseParaGetIdByUid(env, cbInfo, idByUid) == nullptr) {
        ACCOUNT_LOGI("Parse get osaccount local id from uid failed");
        delete idByUid;
        return WrapVoidToJS(env);
    }

    napi_value result = nullptr;
    if (idByUid->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        napi_create_promise(env, &idByUid->deferred, &result);
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "GetOsAccountLocalIdFromUid", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env, nullptr, resource, GetIdByUidExecuteCB, GetIdByUidCallbackCompletedCB,
        reinterpret_cast<void *>(idByUid), &idByUid->work);

    napi_queue_async_work(env, idByUid->work);
    return result;
}

napi_value GetBundleIdFromUid(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("enter");
    GetIdByUidAsyncContext *bundleIdByUid = new (std::nothrow) GetIdByUidAsyncContext();
    if (bundleIdByUid == nullptr) {
        ACCOUNT_LOGI("bundleIdByUid == nullptr");
        return WrapVoidToJS(env);
    }
    bundleIdByUid->env = env;
    bundleIdByUid->callbackRef = nullptr;

    if (ParseParaGetIdByUid(env, cbInfo, bundleIdByUid) == nullptr) {
        ACCOUNT_LOGI("Parse get bundle id from uid failed");
        delete bundleIdByUid;
        return WrapVoidToJS(env);
    }

    napi_value result = nullptr;
    if (bundleIdByUid->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        napi_create_promise(env, &bundleIdByUid->deferred, &result);
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
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

napi_value GetOsAccountLocalIdFromDomain(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("enter");
    GetIdByDomainAsyncContext *idByDomain = new (std::nothrow) GetIdByDomainAsyncContext();
    if (idByDomain == nullptr) {
        ACCOUNT_LOGI("idByDomain == nullptr");
        return WrapVoidToJS(env);
    }
    idByDomain->env = env;
    idByDomain->callbackRef = nullptr;

    if (ParseParaGetIdByDomain(env, cbInfo, idByDomain) == nullptr) {
        ACCOUNT_LOGI("Parse get osaccount local id from uid failed");
        delete idByDomain;
        return WrapVoidToJS(env);
    }

    napi_value result = nullptr;
    if (idByDomain->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        napi_create_promise(env, &idByDomain->deferred, &result);
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "GetOsAccountLocalIdFromDomain", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env, nullptr, resource, GetIdByDomainExecuteCB, GetIdByDomainCallbackCompletedCB,
        reinterpret_cast<void *>(idByDomain), &idByDomain->work);

    napi_queue_async_work(env, idByDomain->work);
    return result;
}

napi_value SetOsAccountProfilePhoto(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("enter");
    SetOAPhotoAsyncContext *setPhoto = new (std::nothrow) SetOAPhotoAsyncContext();
    if (setPhoto == nullptr) {
        ACCOUNT_LOGI("setPhoto == nullptr");
        return WrapVoidToJS(env);
    }
    setPhoto->env = env;
    setPhoto->callbackRef = nullptr;

    if (ParseParaSetPhoto(env, cbInfo, setPhoto) == nullptr) {
        ACCOUNT_LOGI("Parse set profile photo failed");
        delete setPhoto;
        return WrapVoidToJS(env);
    }

    napi_value result = nullptr;
    if (setPhoto->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        napi_create_promise(env, &setPhoto->deferred, &result);
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
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
    ACCOUNT_LOGI("enter");
    QueryMaxNumAsyncContext *maxNum = new (std::nothrow) QueryMaxNumAsyncContext();
    if (maxNum == nullptr) {
        ACCOUNT_LOGI("maxNum == nullptr");
        return WrapVoidToJS(env);
    }
    maxNum->env = env;
    maxNum->callbackRef = nullptr;

    ParseParaQueryMaxNum(env, cbInfo, maxNum);

    napi_value result = nullptr;
    if (maxNum->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        napi_create_promise(env, &maxNum->deferred, &result);
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "QueryMaxOsAccountNumber", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env, nullptr, resource, QueryMaxNumExecuteCB, QueryMaxNumCompletedCB,
        reinterpret_cast<void *>(maxNum), &maxNum->work);

    napi_queue_async_work(env, maxNum->work);
    return result;
}

napi_value IsOsAccountActived(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("enter");
    IsActivedAsyncContext *isActived = new (std::nothrow) IsActivedAsyncContext();
    if (isActived == nullptr) {
        ACCOUNT_LOGI("isActived == nullptr");
        return WrapVoidToJS(env);
    }
    isActived->env = env;
    isActived->callbackRef = nullptr;

    if (ParseParaIsActived(env, cbInfo, isActived) == nullptr) {
        ACCOUNT_LOGI("Parse is osaccount activated failed");
        delete isActived;
        return WrapVoidToJS(env);
    }

    napi_value result = nullptr;
    if (isActived->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        napi_create_promise(env, &isActived->deferred, &result);
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "IsOsAccountActived", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env, nullptr, resource, IsActivedExecuteCB, IsActivedCompletedCB,
        reinterpret_cast<void *>(isActived), &isActived->work);

    napi_queue_async_work(env, isActived->work);
    return result;
}

napi_value IsOsAccountConstraintEnable(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("enter");
    IsConEnableAsyncContext *isEnable = new (std::nothrow) IsConEnableAsyncContext();
    if (isEnable == nullptr) {
        ACCOUNT_LOGI("isEnable == nullptr");
        return WrapVoidToJS(env);
    }
    isEnable->env = env;
    isEnable->callbackRef = nullptr;

    if (ParseParaIsEnable(env, cbInfo, isEnable) == nullptr) {
        ACCOUNT_LOGI("Parse is osaccount constraint enable failed");
        delete isEnable;
        return WrapVoidToJS(env);
    }

    napi_value result = nullptr;
    if (isEnable->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        napi_create_promise(env, &isEnable->deferred, &result);
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "IsOsAccountConstraintEnable", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env, nullptr, resource, IsEnableExecuteCB, IsEnableCompletedCB,
        reinterpret_cast<void *>(isEnable), &isEnable->work);

    napi_queue_async_work(env, isEnable->work);
    return result;
}

napi_value GetOsAccountTypeFromProcess(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("enter");
    GetTypeAsyncContext *getType = new (std::nothrow) GetTypeAsyncContext();
    if (getType == nullptr) {
        ACCOUNT_LOGI("getType == nullptr");
        return WrapVoidToJS(env);
    }
    getType->env = env;
    getType->callbackRef = nullptr;

    ParseParaGetType(env, cbInfo, getType);

    napi_value result = nullptr;
    if (getType->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        napi_create_promise(env, &getType->deferred, &result);
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "GetOsAccountTypeFromProcess", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env, nullptr, resource, GetTypeExecuteCB, GetTypeCompletedCB,
        reinterpret_cast<void *>(getType), &getType->work);

    napi_queue_async_work(env, getType->work);
    return result;
}

napi_value IsMultiOsAccountEnable(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("enter");
    IsMultiEnAsyncContext *multiEn = new (std::nothrow) IsMultiEnAsyncContext();
    if (multiEn == nullptr) {
        ACCOUNT_LOGI("multiEn == nullptr");
        return WrapVoidToJS(env);
    }
    multiEn->env = env;
    multiEn->callbackRef = nullptr;

    ParseParaIsMultiEn(env, cbInfo, multiEn);

    napi_value result = nullptr;
    if (multiEn->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        napi_create_promise(env, &multiEn->deferred, &result);
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "IsMultiOsAccountEnable", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env, nullptr, resource, IsMultiEnExecuteCB, IsMultiEnCompletedCB,
        reinterpret_cast<void *>(multiEn), &multiEn->work);

    napi_queue_async_work(env, multiEn->work);
    return result;
}

napi_value IsOsAccountVerified(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("enter");
    IsVerifiedAsyncContext *isVerified = new (std::nothrow) IsVerifiedAsyncContext();
    if (isVerified == nullptr) {
        ACCOUNT_LOGI("isVerified == nullptr");
        return WrapVoidToJS(env);
    }
    isVerified->env = env;
    isVerified->callbackRef = nullptr;

    if (ParseParaIsVerified(env, cbInfo, isVerified) == nullptr) {
        ACCOUNT_LOGI("Parse is verfied failed");
        delete isVerified;
        return WrapVoidToJS(env);
    }

    napi_value result = nullptr;
    if (isVerified->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        napi_create_promise(env, &isVerified->deferred, &result);
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "IsOsAccountVerified", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env, nullptr, resource, IsVerifiedExecuteCB, IsVerifiedCompletedCB,
        reinterpret_cast<void *>(isVerified), &isVerified->work);

    napi_queue_async_work(env, isVerified->work);
    return result;
}

napi_value GetOsAccountLocalIdBySerialNumber(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("enter");
    GetSerialNumIdCBInfo *serialNumId = new (std::nothrow) GetSerialNumIdCBInfo();
    if (serialNumId == nullptr) {
        ACCOUNT_LOGI("serialNumId == nullptr");
        return WrapVoidToJS(env);
    }
    serialNumId->env = env;
    serialNumId->callbackRef = nullptr;

    if (ParseParaSerialNumId(env, cbInfo, serialNumId) == nullptr) {
        ACCOUNT_LOGI("Parse get local id by serial number failed");
        delete serialNumId;
        return WrapVoidToJS(env);
    }

    napi_value result = nullptr;
    if (serialNumId->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        napi_create_promise(env, &serialNumId->deferred, &result);
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "GetOsAccountLocalIdBySerialNumber", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env, nullptr, resource, SerialNumIdExecuteCB, SerialNumIdCompletedCB,
        reinterpret_cast<void *>(serialNumId), &serialNumId->work);

    napi_queue_async_work(env, serialNumId->work);
    return result;
}

napi_value GetSerialNumberByOsAccountLocalId(napi_env env, napi_callback_info cbInfo)
{
    ACCOUNT_LOGI("enter");
    GetSerialNumForOAInfo *getSerialNum = new (std::nothrow) GetSerialNumForOAInfo();
    if (getSerialNum == nullptr) {
        ACCOUNT_LOGI("getSerialNum == nullptr");
        return WrapVoidToJS(env);
    }
    getSerialNum->env = env;
    getSerialNum->callbackRef = nullptr;

    if (ParseParaGetSerialNum(env, cbInfo, getSerialNum) == nullptr) {
        ACCOUNT_LOGI("Parse get serial number failed");
        delete getSerialNum;
        return WrapVoidToJS(env);
    }

    napi_value result = nullptr;
    if (getSerialNum->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        napi_create_promise(env, &getSerialNum->deferred, &result);
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
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
    ACCOUNT_LOGI("enter");
    IsTestOAInfo *isTest = new (std::nothrow) IsTestOAInfo();
    if (isTest == nullptr) {
        ACCOUNT_LOGI("isTest == nullptr");
        return WrapVoidToJS(env);
    }
    isTest->env = env;
    isTest->callbackRef = nullptr;

    ParseParaIsTestOA(env, cbInfo, isTest);

    napi_value result = nullptr;
    if (isTest->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        napi_create_promise(env, &isTest->deferred, &result);
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
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
            result[PARAMZERO] = GetErrorCodeValue(env, isTest->errCode);
            napi_get_boolean(env, isTest->isTestOsAccount, &result[PARAMONE]);
            CBOrPromiseIsTestOA(env, isTest, result[PARAMZERO], result[PARAMONE]);
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
    ACCOUNT_LOGI("enter");
    IsMainOAInfo *isMain = new (std::nothrow) IsMainOAInfo();
    if (isMain == nullptr) {
        ACCOUNT_LOGI("isMain == nullptr");
        return WrapVoidToJS(env);
    }
    isMain->env = env;
    isMain->callbackRef = nullptr;

    ParseParaIsMainOA(env, cbInfo, isMain);

    napi_value result = nullptr;
    if (isMain->callbackRef == nullptr) {
        ACCOUNT_LOGI("Create promise");
        napi_create_promise(env, &isMain->deferred, &result);
    } else {
        ACCOUNT_LOGI("Undefined the result parameter");
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "IsMainOsAccount", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env,
        nullptr,
        resource,
        [](napi_env env, void *data) {
            ACCOUNT_LOGI("napi_create_async_work running");
            IsMainOAInfo *isMain = reinterpret_cast<IsMainOAInfo *>(data);
            isMain->errCode = OsAccountManager::IsMainOsAccount(isMain->isMainOsAccount);
            ACCOUNT_LOGI("errocde is %{public}d", isMain->errCode);
            isMain->status = (isMain->errCode == 0) ? napi_ok : napi_generic_failure;
        },
        [](napi_env env, napi_status status, void *data) {
            ACCOUNT_LOGI("napi_create_async_work complete");
            IsMainOAInfo *isMain = reinterpret_cast<IsMainOAInfo *>(data);
            napi_value result[RESULT_COUNT] = {0};
            result[PARAMZERO] = GetErrorCodeValue(env, isMain->errCode);
            napi_get_boolean(env, isMain->isMainOsAccount, &result[PARAMONE]);
            CBOrPromiseIsMainOA(env, isMain, result[PARAMZERO], result[PARAMONE]);
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
    ACCOUNT_LOGI("enter");

    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisVar = nullptr;
    napi_ref callback = nullptr;
    std::string onName;
    OS_ACCOUNT_SUBSCRIBE_TYPE onType;

    NAPI_CALL(env, napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, NULL));
    NAPI_ASSERT(env, argc >= ARGS_SIZE_THREE, "Wrong number of arguments");
    ACCOUNT_LOGI("thisVar = %{public}p", thisVar);
    if (ParseParaToSubscriber(env, argv, callback, onType, onName) == nullptr) {
        ACCOUNT_LOGI("Parse subscribe failed");
        return WrapVoidToJS(env);
    }

    SubscribeCBInfo *subscribeCBInfo = new (std::nothrow) SubscribeCBInfo();
    if (subscribeCBInfo == nullptr) {
        ACCOUNT_LOGI("subscribeCBInfo == nullptr");
        return WrapVoidToJS(env);
    }
    subscribeCBInfo->env = env;
    subscribeCBInfo->work = nullptr;
    subscribeCBInfo->callbackRef = callback;
    subscribeCBInfo->name = onName;
    subscribeCBInfo->osSubscribeType = onType;
    ACCOUNT_LOGI("callbackRef = %{public}p", subscribeCBInfo->callbackRef);

    // make osaccount subscribe info
    OsAccountSubscribeInfo subscribeInfo(onType, onName);
    // make a subscriber
    subscribeCBInfo->subscriber = std::make_shared<SubscriberPtr>(subscribeInfo);

    OsAccountManager *objectInfo = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&objectInfo));
    subscribeCBInfo->osManager = objectInfo;
    ACCOUNT_LOGI("OsAccountManager objectInfo = %{public}p", objectInfo);

    {
        std::lock_guard<std::mutex> lock(g_lockForOsAccountSubscribers);
        g_osAccountSubscribers[objectInfo].emplace_back(subscribeCBInfo);
        ACCOUNT_LOGI("g_osAccountSubscribers.size = %{public}zu", g_osAccountSubscribers.size());
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
    ACCOUNT_LOGI("enter");

    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (loop == nullptr) {
        ACCOUNT_LOGI("loop instance is nullptr");
        return;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        ACCOUNT_LOGI("work is null");
        return;
    }

    SubscriberOAWorker *subscriberOAWorker = new (std::nothrow) SubscriberOAWorker();

    if (subscriberOAWorker == nullptr) {
        ACCOUNT_LOGI("SubscriberAccountsWorker is null");
        return;
    }

    subscriberOAWorker->id = id_;
    subscriberOAWorker->env = env_;
    subscriberOAWorker->ref = ref_;
    subscriberOAWorker->subscriber = this;
    work->data = reinterpret_cast<void *>(subscriberOAWorker);
    uv_queue_work(loop, work, [](uv_work_t *work) {}, UvQueueWorkOnAccountsChanged);

    ACCOUNT_LOGI("end");
}

void UvQueueWorkOnAccountsChanged(uv_work_t *work, int status)
{
    ACCOUNT_LOGI("enter");
    if (work == nullptr || work->data == nullptr) {
        return;
    }
    SubscriberOAWorker *subscriberOAWorkerData = reinterpret_cast<SubscriberOAWorker *>(work->data);

    napi_value result[ARGS_SIZE_ONE] = {nullptr};
    napi_create_int32(subscriberOAWorkerData->env, subscriberOAWorkerData->id, &result[PARAMZERO]);

    napi_value undefined = nullptr;
    napi_get_undefined(subscriberOAWorkerData->env, &undefined);

    napi_value callback = nullptr;
    napi_value resultout = nullptr;
    bool isFound = false;
    {
        std::lock_guard<std::mutex> lock(g_lockForOsAccountSubscribers);
        for (auto subscriberInstance : g_osAccountSubscribers) {
            for (auto item : subscriberInstance.second) {
                if (item->subscriber.get() == subscriberOAWorkerData->subscriber) {
                    isFound = true;
                    break;
                }
            }
            if (isFound) {
                break;
            }
        }
        if (!isFound) {
            ACCOUNT_LOGI("subscriber has already been deleted, ignore callback.");
        } else {
            ACCOUNT_LOGI("subscriber has been found.");
            napi_get_reference_value(subscriberOAWorkerData->env, subscriberOAWorkerData->ref, &callback);
        }
    }
    if (isFound) {
        NAPI_CALL_RETURN_VOID(subscriberOAWorkerData->env,
            napi_call_function(subscriberOAWorkerData->env, undefined, callback, ARGS_SIZE_ONE, &result[0],
                &resultout));
    }
    delete subscriberOAWorkerData;
    subscriberOAWorkerData = nullptr;
    delete work;

    ACCOUNT_LOGI("end");
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
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisVar = nullptr;
    std::string offName;
    OS_ACCOUNT_SUBSCRIBE_TYPE offType;

    NAPI_CALL(env, napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, NULL));
    NAPI_ASSERT(env, argc >= ARGS_SIZE_TWO, "Wrong number of arguments");
    ACCOUNT_LOGI("Unsubscribe thisVar = %{public}p", thisVar);

    napi_ref callback = nullptr;
    if (ParseParaToUnsubscriber(env, argc, argv, callback, offType, offName) == nullptr) {
        ACCOUNT_LOGI("Parse unsubscribe failed");
        return WrapVoidToJS(env);
    }

    UnsubscribeCBInfo *unsubscribeCBInfo = new (std::nothrow) UnsubscribeCBInfo();
    if (unsubscribeCBInfo == nullptr) {
        ACCOUNT_LOGI("unsubscribeCBInfo == nullptr");
        return WrapVoidToJS(env);
    }

    OsAccountManager *objectInfo = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&objectInfo));
    unsubscribeCBInfo->osManager = objectInfo;
    unsubscribeCBInfo->callbackRef = callback;
    unsubscribeCBInfo->osSubscribeType = offType;
    unsubscribeCBInfo->name = offName;
    unsubscribeCBInfo->argc = argc;

    bool isFind = false;
    std::vector<std::shared_ptr<SubscriberPtr>> subscribers;
    FindSubscriberInMap(subscribers, unsubscribeCBInfo, isFind);
    if (!isFind) {
        ACCOUNT_LOGI("Unsubscribe failed. The current subscriber does not exist");
        return WrapVoidToJS(env);
    }
    unsubscribeCBInfo->subscribers = subscribers;
    ACCOUNT_LOGI("UnsubscribeExecuteCB Off size = %{public}zu", unsubscribeCBInfo->subscribers.size());

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
    ACCOUNT_LOGI("enter");

    std::lock_guard<std::mutex> lock(g_lockForOsAccountSubscribers);

    ACCOUNT_LOGI("g_osAccountSubscribers.size = %{public}zu", g_osAccountSubscribers.size());
    for (auto subscriberInstance : g_osAccountSubscribers) {
        ACCOUNT_LOGI("Through map to get the subscribe objectInfo = %{public}p", subscriberInstance.first);
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
    ACCOUNT_LOGI("napi_create_async_work running");
    UnsubscribeCBInfo *unsubscribeCBInfo = reinterpret_cast<UnsubscribeCBInfo *>(data);
    ACCOUNT_LOGI("UnsubscribeExecuteCB Off size = %{public}zu", unsubscribeCBInfo->subscribers.size());
    for (auto offSubscriber : unsubscribeCBInfo->subscribers) {
        int errCode = OsAccountManager::UnsubscribeOsAccount(offSubscriber);
        ACCOUNT_LOGI("errocde is %{public}d", errCode);
    }
}

void UnsubscribeCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete.");
    UnsubscribeCBInfo *unsubscribeCBInfo = reinterpret_cast<UnsubscribeCBInfo *>(data);
    if (unsubscribeCBInfo == nullptr) {
        return;
    }

    if (unsubscribeCBInfo->argc >= ARGS_SIZE_THREE) {
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
    }

    if (unsubscribeCBInfo->callbackRef != nullptr) {
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
                    ACCOUNT_LOGI("Erace vector, vector.size = %{public}zu", subscribe->second.size());
                } else {
                    ++it;
                }
            }

            if (subscribe->second.size() == 0) {
                ACCOUNT_LOGI("No subscriberInfo in the vector, erase the map");
                g_osAccountSubscribers.erase(subscribe);
            }
            ACCOUNT_LOGI("Earse end g_osAccountSubscribers.size = %{public}zu", g_osAccountSubscribers.size());
        }
    }

    delete unsubscribeCBInfo;
    unsubscribeCBInfo = nullptr;
}
}  // namespace AccountJsKit
}  // namespace OHOS
