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

#include "napi_os_account_common.h"
#include <string>
#include "napi_account_error.h"
#include "napi_account_common.h"
#include "napi/native_common.h"
#include "napi_os_account.h"

namespace OHOS {
namespace AccountJsKit {
napi_value WrapVoidToJS(napi_env env)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    return result;
}

static bool ParseOneParaContext(napi_env env, napi_callback_info cbInfo, CommonAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc == ARGS_SIZE_ONE) {
        if (!GetCallbackProperty(env, argv[argc - 1], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            std::string errMsg = "The type of arg " + std::to_string(argc) + " must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
    }
    return true;
}

bool ParseParaQueryOAByIdCB(napi_env env, napi_callback_info cbInfo, QueryOAByIdAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc == ARGS_SIZE_TWO) {
        if (!GetCallbackProperty(env, argv[argc - 1], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            std::string errMsg = "The type of arg " + std::to_string(argc) + " must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
    }
    if (!GetIntProperty(env, argv[PARAMZERO], asyncContext->id)) {
        ACCOUNT_LOGE("Get id failed");
        std::string errMsg = "The type of arg 1 must be number";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    return true;
}

void QueryOAByIdExecuteCB(napi_env env, void *data)
{
    QueryOAByIdAsyncContext *asyncContext = reinterpret_cast<QueryOAByIdAsyncContext *>(data);
    asyncContext->errCode = OsAccountManager::QueryOsAccountById(asyncContext->id, asyncContext->osAccountInfos);
    ACCOUNT_LOGD("errcode is %{public}d", asyncContext->errCode);
    asyncContext->status = (asyncContext->errCode == 0) ? napi_ok : napi_generic_failure;
}

void QueryOAByIdCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    QueryOAByIdAsyncContext *asyncContext = reinterpret_cast<QueryOAByIdAsyncContext *>(data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->status == napi_ok) {
        napi_get_null(env, &errJs);
        GetOACBInfoToJs(env, asyncContext->osAccountInfos, dataJs);
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode, asyncContext->throwErr);
        napi_get_null(env, &dataJs);
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
    napi_delete_async_work(env, asyncContext->work);
    delete asyncContext;
    asyncContext = nullptr;
}

void CreateJsDomainInfo(napi_env env, const DomainAccountInfo &info, napi_value &result)
{
    napi_create_object(env, &result);
    napi_value value = nullptr;
    // domain
    napi_create_string_utf8(env, info.domain_.c_str(), info.domain_.size(), &value);
    napi_set_named_property(env, result, "domain", value);

    // domain accountName
    napi_create_string_utf8(env, info.accountName_.c_str(), info.accountName_.size(), &value);
    napi_set_named_property(env, result, "accountName", value);
}

void CreateJsDistributedInfo(napi_env env, const OhosAccountInfo &info, napi_value &result)
{
    napi_create_object(env, &result);
    napi_value value = nullptr;
    // name
    napi_create_string_utf8(env, info.name_.c_str(), info.name_.size(), &value);
    napi_set_named_property(env, result, "name", value);

    // id
    napi_create_string_utf8(env, info.uid_.c_str(), info.uid_.size(), &value);
    napi_set_named_property(env, result, "id", value);

    // event
    napi_create_string_utf8(env, "", 0, &value);
    napi_set_named_property(env, result, "event", value);

    // scalableData
    napi_value scalable = nullptr;
    napi_create_object(env, &scalable);
    napi_set_named_property(env, result, "scalableData", scalable);
}

void GetOACBInfoToJs(napi_env env, OsAccountInfo &info, napi_value &objOAInfo)
{
    napi_create_object(env, &objOAInfo);
    // localId
    napi_value idToJs = nullptr;
    napi_create_int32(env, info.GetLocalId(), &idToJs);
    napi_set_named_property(env, objOAInfo, "localId", idToJs);

    // localName
    napi_value nameToJs = nullptr;
    napi_create_string_utf8(env, info.GetLocalName().c_str(), NAPI_AUTO_LENGTH, &nameToJs);
    napi_set_named_property(env, objOAInfo, "localName", nameToJs);

    // type
    napi_value typeToJsObj = nullptr;
    napi_create_int32(env, static_cast<int>(info.GetType()), &typeToJsObj);
    napi_set_named_property(env, objOAInfo, "type", typeToJsObj);

    // constraints
    napi_value constraintsToJs = nullptr;
    napi_create_array(env, &constraintsToJs);
    MakeArrayToJs(env, info.GetConstraints(), constraintsToJs);
    napi_set_named_property(env, objOAInfo, "constraints", constraintsToJs);

    // isVerified
    napi_value isVerifiedToJs = nullptr;
    napi_get_boolean(env, info.GetIsVerified(), &isVerifiedToJs);
    napi_set_named_property(env, objOAInfo, "isVerified", isVerifiedToJs);

    // photo
    napi_value photoToJs = nullptr;
    napi_create_string_utf8(env, info.GetPhoto().c_str(), NAPI_AUTO_LENGTH, &photoToJs);
    napi_set_named_property(env, objOAInfo, "photo", photoToJs);

    // createTime
    napi_value createTimeToJs = nullptr;
    napi_create_int64(env, info.GetCreateTime(), &createTimeToJs);
    napi_set_named_property(env, objOAInfo, "createTime", createTimeToJs);

    // lastLoginTime
    napi_value lastLoginTimeToJs = nullptr;
    napi_create_int64(env, info.GetLastLoginTime(), &lastLoginTimeToJs);
    napi_set_named_property(env, objOAInfo, "lastLoginTime", lastLoginTimeToJs);

    // serialNumber
    napi_value serialNumberToJs = nullptr;
    napi_create_int64(env, info.GetSerialNumber(), &serialNumberToJs);
    napi_set_named_property(env, objOAInfo, "serialNumber", serialNumberToJs);

    // isActived
    napi_value isActivedToJs = nullptr;
    napi_get_boolean(env, info.GetIsActived(), &isActivedToJs);
    napi_set_named_property(env, objOAInfo, "isActived", isActivedToJs);

    // isCreateCompleted
    napi_value isCreateCompletedToJs = nullptr;
    napi_get_boolean(env, info.GetIsCreateCompleted(), &isCreateCompletedToJs);
    napi_set_named_property(env, objOAInfo, "isCreateCompleted", isCreateCompletedToJs);

    // distributedInfo: distributedAccount.DistributedInfo
    napi_value dbInfoToJs = nullptr;
    std::pair<bool, OhosAccountInfo> dbAccountInfo = OhosAccountKits::GetInstance().QueryOhosAccountInfo();
    if (dbAccountInfo.first) {
        CreateJsDistributedInfo(env, dbAccountInfo.second, dbInfoToJs);
    }
    napi_set_named_property(env, objOAInfo, "distributedInfo", dbInfoToJs);

    // domainInfo: domainInfo.DomainAccountInfo
    DomainAccountInfo domainInfo;
    info.GetDomainInfo(domainInfo);
    CreateJsDomainInfo(env, domainInfo, dbInfoToJs);
    napi_set_named_property(env, objOAInfo, "domainInfo", dbInfoToJs);
}

void MakeArrayToJs(napi_env env, const std::vector<std::string> &constraints, napi_value jsArray)
{
    uint32_t index = 0;

    for (auto item : constraints) {
        napi_value constraint = nullptr;
        napi_create_string_utf8(env, item.c_str(), NAPI_AUTO_LENGTH, &constraint);
        napi_set_element(env, jsArray, index, constraint);
        index++;
    }
}

bool ParseParaRemoveOACB(napi_env env, napi_callback_info cbInfo, RemoveOAAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    if (argc == ARGS_SIZE_TWO) {
        if (!GetCallbackProperty(env, argv[argc - 1], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            std::string errMsg = "The type of arg " + std::to_string(argc) + " must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
    }

    if (!GetIntProperty(env, argv[PARAMZERO], asyncContext->id)) {
        ACCOUNT_LOGE("Get id failed");
        std::string errMsg = "The type of arg 1 must be number";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    return true;
}

void RemoveOAExecuteCB(napi_env env, void *data)
{
    RemoveOAAsyncContext *asyncContext = reinterpret_cast<RemoveOAAsyncContext *>(data);
    asyncContext->errCode = OsAccountManager::RemoveOsAccount(asyncContext->id);
    ACCOUNT_LOGD("errcode is %{public}d", asyncContext->errCode);
    asyncContext->status = (asyncContext->errCode == 0) ? napi_ok : napi_generic_failure;
}

void RemoveOACallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGD("napi_create_async_work complete");
    RemoveOAAsyncContext *asyncContext = reinterpret_cast<RemoveOAAsyncContext *>(data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->status == napi_ok) {
        napi_get_null(env, &errJs);
        napi_get_null(env, &dataJs);
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode, asyncContext->throwErr);
        napi_get_null(env, &dataJs);
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
    napi_delete_async_work(env, asyncContext->work);
    delete asyncContext;
    asyncContext = nullptr;
}

bool ParseParaSetOAName(napi_env env, napi_callback_info cbInfo, SetOANameAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    if (argc == ARGS_SIZE_THREE) {
        if (!GetCallbackProperty(env, argv[argc - 1], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            std::string errMsg = "The type of arg " + std::to_string(argc) + " must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
    }

    if (!GetIntProperty(env, argv[PARAMZERO], asyncContext->id)) {
        ACCOUNT_LOGE("Get id failed");
        std::string errMsg = "The type of arg 1 must be number";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    if (!GetStringProperty(env, argv[PARAMONE], asyncContext->name)) {
        ACCOUNT_LOGE("Get name failed");
        std::string errMsg = "The type of arg 2 must be string";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    
    return true;
}

void SetOANameExecuteCB(napi_env env, void *data)
{
    SetOANameAsyncContext *asyncContext = reinterpret_cast<SetOANameAsyncContext *>(data);
    asyncContext->errCode = OsAccountManager::SetOsAccountName(asyncContext->id, asyncContext->name);
    ACCOUNT_LOGD("errcode is %{public}d", asyncContext->errCode);
    asyncContext->status = (asyncContext->errCode == 0) ? napi_ok : napi_generic_failure;
}

void SetOANameCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGD("napi_create_async_work complete");
    SetOANameAsyncContext *asyncContext = reinterpret_cast<SetOANameAsyncContext *>(data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->status == napi_ok) {
        napi_get_null(env, &errJs);
        napi_get_null(env, &dataJs);
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode, asyncContext->throwErr);
        napi_get_null(env, &dataJs);
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
    napi_delete_async_work(env, asyncContext->work);
    delete asyncContext;
    asyncContext = nullptr;
}

bool ParseParaSetOAConstraints(napi_env env, napi_callback_info cbInfo, SetOAConsAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = {0};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr), false);

    // argv[3] : callback
    if (argc == ARGS_SIZE_FOUR) {
        if (!GetCallbackProperty(env, argv[argc - 1], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            std::string errMsg = "The type of arg " + std::to_string(argc) + " must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
    }

    // argv[0] : localId
    if (!GetIntProperty(env, argv[PARAMZERO], asyncContext->id)) {
        ACCOUNT_LOGE("Get id failed");
        std::string errMsg = "The type of arg 1 must be number";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }

    // argv[1] : Array<string>
    if (!GetStringArrayProperty(env, argv[PARAMONE], asyncContext->constraints, false)) {
        ACCOUNT_LOGE("Get constraints failed, expected array of strings");
        std::string errMsg = "The type of arg 2 must be unempty array of strings";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }

    // argv[2] : enable
    if (!GetBoolProperty(env, argv[PARAMTWO], asyncContext->enable)) {
        ACCOUNT_LOGE("Get enable failed");
        std::string errMsg = "The type of arg 3 must be boolean";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }

    return true;
}

void SetOAConsExecuteCB(napi_env env, void *data)
{
    SetOAConsAsyncContext *asyncContext = reinterpret_cast<SetOAConsAsyncContext *>(data);
    asyncContext->errCode =
        OsAccountManager::SetOsAccountConstraints(asyncContext->id, asyncContext->constraints, asyncContext->enable);
    ACCOUNT_LOGD("errcode is %{public}d", asyncContext->errCode);
    asyncContext->status = (asyncContext->errCode == 0) ? napi_ok : napi_generic_failure;
}

void SetOAConsCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGD("napi_create_async_work complete");
    SetOAConsAsyncContext *asyncContext = reinterpret_cast<SetOAConsAsyncContext *>(data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->status == napi_ok) {
        napi_get_null(env, &errJs);
        napi_get_null(env, &dataJs);
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode, asyncContext->throwErr);
        napi_get_null(env, &dataJs);
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
    napi_delete_async_work(env, asyncContext->work);
    delete asyncContext;
    asyncContext = nullptr;
}

bool ParseParaActiveOA(napi_env env, napi_callback_info cbInfo, ActivateOAAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    if (argc == ARGS_SIZE_TWO) {
        if (!GetCallbackProperty(env, argv[argc - 1], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            std::string errMsg = "The type of arg " + std::to_string(argc) + " must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
    }

    if (!GetIntProperty(env, argv[PARAMZERO], asyncContext->id)) {
        ACCOUNT_LOGE("Get id failed");
        std::string errMsg = "The type of arg 1 must be number";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }

    return true;
}

void ActivateOAExecuteCB(napi_env env, void *data)
{
    ActivateOAAsyncContext *activateOACB = reinterpret_cast<ActivateOAAsyncContext *>(data);
    activateOACB->errCode = OsAccountManager::ActivateOsAccount(activateOACB->id);
    ACCOUNT_LOGD("errcode is %{public}d", activateOACB->errCode);
    activateOACB->status = (activateOACB->errCode == 0) ? napi_ok : napi_generic_failure;
}

void ActivateOACallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGD("napi_create_async_work complete");
    ActivateOAAsyncContext *asyncContext = reinterpret_cast<ActivateOAAsyncContext *>(data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->status == napi_ok) {
        napi_get_null(env, &errJs);
        napi_get_null(env, &dataJs);
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode, asyncContext->throwErr);
        napi_get_null(env, &dataJs);
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
    napi_delete_async_work(env, asyncContext->work);
    delete asyncContext;
    asyncContext = nullptr;
}

bool ParseParaCreateOA(napi_env env, napi_callback_info cbInfo, CreateOAAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    if (argc == ARGS_SIZE_THREE) {
        if (!GetCallbackProperty(env, argv[argc - 1], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            std::string errMsg = "The type of arg " + std::to_string(argc) + " must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
    }

    if (!GetStringProperty(env, argv[PARAMZERO], asyncContext->name)) {
        ACCOUNT_LOGE("Get name failed");
        std::string errMsg = "The type of arg 1 must be string";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    int32_t type = 0;
    if (!GetIntProperty(env, argv[PARAMONE], type)) {
        ACCOUNT_LOGE("Get type failed");
        std::string errMsg = "The type of arg 2 must be number";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    asyncContext->type = static_cast<OsAccountType>(type);
    return true;
}

bool ParseParaCreateOAForDomain(napi_env env, napi_callback_info cbInfo,
    CreateOAForDomainAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    if (argc == ARGS_SIZE_THREE) {
        if (!GetCallbackProperty(env, argv[argc - 1], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            std::string errMsg = "The type of arg " + std::to_string(argc) + " must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
    }

    int32_t id = 0;
    if (!GetIntProperty(env, argv[PARAMZERO], id)) {
        ACCOUNT_LOGE("Get id failed");
        std::string errMsg = "The type of arg 1 must be number";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    asyncContext->type = static_cast<OsAccountType>(id);

    if (!GetStringPropertyByKey(env, argv[PARAMONE], "domain", asyncContext->domainInfo.domain_)) {
        ACCOUNT_LOGE("Get domainInfo's domain failed");
        std::string errMsg = "The type of arg 2's domain must be string";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    if (!GetStringPropertyByKey(env, argv[PARAMONE], "accountName", asyncContext->domainInfo.accountName_)) {
        ACCOUNT_LOGE("Get domainInfo's accountName failed");
        std::string errMsg = "The type of arg 2's accountName must be string";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    return true;
}

void CreateOAExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGD("napi_create_async_work running");
    CreateOAAsyncContext *asyncContext = reinterpret_cast<CreateOAAsyncContext *>(data);
    asyncContext->errCode =
        OsAccountManager::CreateOsAccount(asyncContext->name, asyncContext->type, asyncContext->osAccountInfos);
    asyncContext->status = (asyncContext->errCode == 0) ? napi_ok : napi_generic_failure;
}

void CreateOAForDomainExecuteCB(napi_env env, void *data)
{
    CreateOAForDomainAsyncContext *asyncContext = reinterpret_cast<CreateOAForDomainAsyncContext *>(data);
    asyncContext->errCode = OsAccountManager::CreateOsAccountForDomain(asyncContext->type,
        asyncContext->domainInfo, asyncContext->osAccountInfos);
    ACCOUNT_LOGD("error code is %{public}d", asyncContext->errCode);
    asyncContext->status = (asyncContext->errCode == 0) ? napi_ok : napi_generic_failure;
}

void CreateOACallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGD("napi_create_async_work complete");
    CreateOAAsyncContext *asyncContext = reinterpret_cast<CreateOAAsyncContext *>(data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->status == napi_ok) {
        napi_get_null(env, &errJs);
        GetOACBInfoToJs(env, asyncContext->osAccountInfos, dataJs);
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode, asyncContext->throwErr);
        napi_get_null(env, &dataJs);
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
    napi_delete_async_work(env, asyncContext->work);
    delete asyncContext;
    asyncContext = nullptr;
}

void CreateOAForDomainCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    CreateOAForDomainAsyncContext *asyncContext = reinterpret_cast<CreateOAForDomainAsyncContext *>(data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->status == napi_ok) {
        napi_get_null(env, &errJs);
        GetOACBInfoToJs(env, asyncContext->osAccountInfos, dataJs);
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode, asyncContext->throwErr);
        napi_get_null(env, &dataJs);
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
    napi_delete_async_work(env, asyncContext->work);
    delete asyncContext;
    asyncContext = nullptr;
}

bool ParseParaGetOACount(napi_env env, napi_callback_info cbInfo, GetOACountAsyncContext *asyncContext)
{
    return ParseOneParaContext(env, cbInfo, asyncContext);
}

void GetOACountExecuteCB(napi_env env, void *data)
{
    GetOACountAsyncContext *asyncContext = reinterpret_cast<GetOACountAsyncContext *>(data);
    asyncContext->errCode = OsAccountManager::GetCreatedOsAccountsCount(asyncContext->osAccountsCount);
    // for compatibility
    if ((!asyncContext->throwErr) && (asyncContext->errCode == ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED)) {
        asyncContext->errCode = ERR_OSACCOUNT_KIT_GET_CREATED_OS_ACCOUNT_COUNT_ERROR;
    }
    asyncContext->status = (asyncContext->errCode == 0) ? napi_ok : napi_generic_failure;
}

void GetOACountCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGD("napi_create_async_work complete");
    GetOACountAsyncContext *asyncContext = reinterpret_cast<GetOACountAsyncContext *>(data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->status == napi_ok) {
        errJs = GenerateBusinessSuccess(env, asyncContext->throwErr);
        napi_create_uint32(env, asyncContext->osAccountsCount, &dataJs);
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode, asyncContext->throwErr);
        if (asyncContext->throwErr) {
            napi_get_null(env, &dataJs);
        } else {
            napi_create_uint32(env, asyncContext->osAccountsCount, &dataJs);
        }
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
    napi_delete_async_work(env, asyncContext->work);
    delete asyncContext;
    asyncContext = nullptr;
}

bool ParseParaDbDeviceId(napi_env env, napi_callback_info cbInfo, DbDeviceIdAsyncContext *asyncContext)
{
    return ParseOneParaContext(env, cbInfo, asyncContext);
}

void DbDeviceIdExecuteCB(napi_env env, void *data)
{
    DbDeviceIdAsyncContext *asyncContext = reinterpret_cast<DbDeviceIdAsyncContext *>(data);
    asyncContext->errCode = OsAccountManager::GetDistributedVirtualDeviceId(asyncContext->deviceId);
    ACCOUNT_LOGD("error code is %{public}d", asyncContext->errCode);
    asyncContext->status = (asyncContext->errCode == 0) ? napi_ok : napi_generic_failure;
}

void DbDeviceIdCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGD("napi_create_async_work complete");
    DbDeviceIdAsyncContext *asyncContext = reinterpret_cast<DbDeviceIdAsyncContext *>(data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->status == napi_ok) {
        errJs = GenerateBusinessSuccess(env, asyncContext->throwErr);
        napi_create_string_utf8(env, asyncContext->deviceId.c_str(), NAPI_AUTO_LENGTH, &dataJs);
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode, asyncContext->throwErr);
        if (asyncContext->throwErr) {
            napi_get_null(env, &dataJs);
        } else {
            napi_create_string_utf8(env, asyncContext->deviceId.c_str(), NAPI_AUTO_LENGTH, &dataJs);
        }
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
    napi_delete_async_work(env, asyncContext->work);
    delete asyncContext;
    asyncContext = nullptr;
}

bool ParseParaGetAllCons(napi_env env, napi_callback_info cbInfo, GetAllConsAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    if (argc == ARGS_SIZE_TWO) {
        if (!GetCallbackProperty(env, argv[argc - 1], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            std::string errMsg = "The type of arg " + std::to_string(argc) + " must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
    }

    if (!GetIntProperty(env, argv[PARAMZERO], asyncContext->id)) {
        ACCOUNT_LOGE("Get id failed");
        std::string errMsg = "The type of arg 1 must be number";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }

    return true;
}

void GetAllConsExecuteCB(napi_env env, void *data)
{
    GetAllConsAsyncContext *asyncContext = reinterpret_cast<GetAllConsAsyncContext *>(data);
    asyncContext->errCode = OsAccountManager::GetOsAccountAllConstraints(asyncContext->id, asyncContext->constraints);
    // for compatibility
    if ((!asyncContext->throwErr) && (asyncContext->errCode == ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED)) {
        asyncContext->errCode = ERR_OSACCOUNT_KIT_GET_OS_ACCOUNT_ALL_CONSTRAINTS_ERROR;
    }
    asyncContext->status = (asyncContext->errCode == 0) ? napi_ok : napi_generic_failure;
}

void GetAllConsCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGD("napi_create_async_work complete");
    GetAllConsAsyncContext *asyncContext = reinterpret_cast<GetAllConsAsyncContext *>(data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->status == napi_ok) {
        errJs = GenerateBusinessSuccess(env, asyncContext->throwErr);
        GetAllAccountCons(env, asyncContext->constraints, dataJs);
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode, asyncContext->throwErr);
        if (asyncContext->throwErr) {
            napi_get_null(env, &dataJs);
        } else {
            GetAllAccountCons(env, asyncContext->constraints, dataJs);
        }
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
    napi_delete_async_work(env, asyncContext->work);
    delete asyncContext;
    asyncContext = nullptr;
}

void GetAllAccountCons(napi_env env, const std::vector<std::string> &info, napi_value &result)
{
    napi_create_array(env, &result);
    uint32_t index = 0;

    for (auto item : info) {
        napi_value consStr = nullptr;
        napi_create_string_utf8(env, item.c_str(), NAPI_AUTO_LENGTH, &consStr);
        napi_set_element(env, result, index, consStr);
        index++;
    }
}

void GetActiveIds(napi_env env, const std::vector<int> &ids, napi_value &result)
{
    napi_create_array(env, &result);
    uint32_t index = 0;

    for (auto id : ids) {
        napi_value tempID = nullptr;
        napi_create_int32(env, id, &tempID);
        napi_set_element(env, result, index, tempID);
        index++;
    }
}

bool ParseParaProcessId(napi_env env, napi_callback_info cbInfo, GetIdAsyncContext *asyncContext)
{
    return ParseOneParaContext(env, cbInfo, asyncContext);
}

void GetProcessIdExecuteCB(napi_env env, void *data)
{
    GetIdAsyncContext *asyncContext = reinterpret_cast<GetIdAsyncContext *>(data);
    asyncContext->errCode = OsAccountManager::GetOsAccountLocalIdFromProcess(asyncContext->id);
    ACCOUNT_LOGD("error code is %{public}d", asyncContext->errCode);
    asyncContext->status = (asyncContext->errCode == 0) ? napi_ok : napi_generic_failure;
}

void GetProcessIdCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGD("napi_create_async_work complete");
    GetIdAsyncContext *asyncContext = reinterpret_cast<GetIdAsyncContext *>(data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->status == napi_ok) {
        errJs = GenerateBusinessSuccess(env, asyncContext->throwErr);
        napi_create_int32(env, asyncContext->id, &dataJs);
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode, asyncContext->throwErr);
        if (asyncContext->throwErr) {
            napi_get_null(env, &dataJs);
        } else {
            napi_create_int32(env, asyncContext->id, &dataJs);
        }
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
    napi_delete_async_work(env, asyncContext->work);
    delete asyncContext;
    asyncContext = nullptr;
}

bool ParseQueryAllCreateOA(napi_env env, napi_callback_info cbInfo, QueryCreateOAAsyncContext *asyncContext)
{
    return ParseOneParaContext(env, cbInfo, asyncContext);
}

bool ParseQueryOAConstraintSrcTypes(napi_env env, napi_callback_info cbInfo,
    QueryOAConstraintSrcTypeContext *asyncContext)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc == ARGS_SIZE_THREE) {
        if (!GetCallbackProperty(env, argv[argc - 1], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            std::string errMsg = "The type of arg " + std::to_string(argc) + " must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
    }

    if (!GetIntProperty(env, argv[PARAMZERO], asyncContext->id)) {
        ACCOUNT_LOGE("Get id failed");
        std::string errMsg = "The type of arg 1 must be number";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    if (!GetStringProperty(env, argv[PARAMONE], asyncContext->constraint)) {
        ACCOUNT_LOGE("Get constraint failed");
        std::string errMsg = "The type of arg 2 must be string";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }

    return true;
}

void QueryOAContSrcTypeExecuteCB(napi_env env, void *data)
{
    QueryOAConstraintSrcTypeContext *asyncContext = reinterpret_cast<QueryOAConstraintSrcTypeContext *>(data);
    asyncContext->errCode = OsAccountManager::QueryOsAccountConstraintSourceTypes(asyncContext->id,
        asyncContext->constraint, asyncContext->constraintSourceTypeInfos);
    ACCOUNT_LOGI("errocde is %{public}d", asyncContext->errCode);
    asyncContext->status = (asyncContext->errCode == 0) ? napi_ok : napi_generic_failure;
}

void QueryOAContSrcTypeCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    QueryOAConstraintSrcTypeContext *asyncContext = reinterpret_cast<QueryOAConstraintSrcTypeContext *>(data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->status == napi_ok) {
        napi_get_null(env, &errJs);
        QueryOAContSrcTypeForResult(env, asyncContext->constraintSourceTypeInfos, dataJs);
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode, asyncContext->throwErr);
        napi_get_null(env, &dataJs);
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
    napi_delete_async_work(env, asyncContext->work);
    delete asyncContext;
    asyncContext = nullptr;
}

void QueryOAContSrcTypeForResult(napi_env env, const std::vector<ConstraintSourceTypeInfo> &infos, napi_value &result)
{
    napi_create_array(env, &result);
    uint32_t index = 0;

    for (auto item : infos) {
        napi_value objTypeInfo = nullptr;
        napi_create_object(env, &objTypeInfo);
        
        napi_value srcLocalId = nullptr;
        napi_create_int32(env, item.localId, &srcLocalId);
        napi_set_named_property(env, objTypeInfo, "localId", srcLocalId);

        napi_value valToJs = nullptr;
        napi_create_int32(env, item.typeInfo, &valToJs);

        napi_set_named_property(env, objTypeInfo, "ConstraintSourceType", valToJs);
        napi_set_element(env, result, index, objTypeInfo);
        index++;
    }
}

bool ParseQueryActiveIds(napi_env env, napi_callback_info cbInfo, QueryActiveIdsAsyncContext *asyncContext)
{
    return ParseOneParaContext(env, cbInfo, asyncContext);
}

void QueryCreateOAExecuteCB(napi_env env, void *data)
{
    QueryCreateOAAsyncContext *asyncContext = reinterpret_cast<QueryCreateOAAsyncContext *>(data);
    asyncContext->errCode = OsAccountManager::QueryAllCreatedOsAccounts(asyncContext->osAccountInfos);
    ACCOUNT_LOGD("error code is %{public}d", asyncContext->errCode);
    asyncContext->status = (asyncContext->errCode == 0) ? napi_ok : napi_generic_failure;
}

void QueryActiveIdsExecuteCB(napi_env env, void *data)
{
    QueryActiveIdsAsyncContext *asyncContext = reinterpret_cast<QueryActiveIdsAsyncContext *>(data);
    asyncContext->errCode = OsAccountManager::QueryActiveOsAccountIds(asyncContext->osAccountIds);
    ACCOUNT_LOGD("error code is %{public}d", asyncContext->errCode);
    asyncContext->status = (asyncContext->errCode == 0) ? napi_ok : napi_generic_failure;
}

void QueryCreateOACallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGD("napi_create_async_work complete");
    QueryCreateOAAsyncContext *asyncContext = reinterpret_cast<QueryCreateOAAsyncContext *>(data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->status == napi_ok) {
        napi_get_null(env, &errJs);
        QueryOAInfoForResult(env, asyncContext->osAccountInfos, dataJs);
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode, asyncContext->throwErr);
        napi_get_null(env, &dataJs);
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
    napi_delete_async_work(env, asyncContext->work);
    delete asyncContext;
    asyncContext = nullptr;
}

void QueryActiveIdsCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGD("napi_create_async_work complete");
    QueryActiveIdsAsyncContext *asyncContext = reinterpret_cast<QueryActiveIdsAsyncContext *>(data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->status == napi_ok) {
        errJs = GenerateBusinessSuccess(env, asyncContext->throwErr);
        GetActiveIds(env, asyncContext->osAccountIds, dataJs);
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode, asyncContext->throwErr);
        if (asyncContext->throwErr) {
            napi_get_null(env, &dataJs);
        } else {
            GetActiveIds(env, asyncContext->osAccountIds, dataJs);
        }
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
    napi_delete_async_work(env, asyncContext->work);
    delete asyncContext;
    asyncContext = nullptr;
}

void QueryOAInfoForResult(napi_env env, const std::vector<OsAccountInfo> &info, napi_value &result)
{
    napi_create_array(env, &result);
    uint32_t index = 0;

    for (auto item : info) {
        napi_value objOAInfo = nullptr;
        napi_create_object(env, &objOAInfo);
        GetOACBInfoToJs(env, item, objOAInfo);
        napi_set_element(env, result, index, objOAInfo);
        index++;
    }
}

bool ParseParaGetPhoto(napi_env env, napi_callback_info cbInfo, GetOAPhotoAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc == ARGS_SIZE_TWO) {
        if (!GetCallbackProperty(env, argv[argc - 1], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            std::string errMsg = "The type of arg " + std::to_string(argc) + " must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
    }

    if (!GetIntProperty(env, argv[PARAMZERO], asyncContext->id)) {
        ACCOUNT_LOGE("Get id failed");
        std::string errMsg = "The type of arg 1 must be number";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    return true;
}

void GetOAPhotoExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGD("napi_create_async_work running");
    GetOAPhotoAsyncContext *asyncContext = reinterpret_cast<GetOAPhotoAsyncContext *>(data);
    asyncContext->errCode = OsAccountManager::GetOsAccountProfilePhoto(asyncContext->id, asyncContext->photo);
    asyncContext->status = (asyncContext->errCode == 0) ? napi_ok : napi_generic_failure;
}

void GetOAPhotoCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGD("napi_create_async_work complete");
    GetOAPhotoAsyncContext *asyncContext = reinterpret_cast<GetOAPhotoAsyncContext *>(data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->status == napi_ok) {
        napi_get_null(env, &errJs);
        napi_create_string_utf8(env, asyncContext->photo.c_str(), NAPI_AUTO_LENGTH, &dataJs);
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode, asyncContext->throwErr);
        napi_get_null(env, &dataJs);
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
    napi_delete_async_work(env, asyncContext->work);
    delete asyncContext;
    asyncContext = nullptr;
}

bool ParseParaCurrentOA(napi_env env, napi_callback_info cbInfo, CurrentOAAsyncContext *asyncContext)
{
    return ParseOneParaContext(env, cbInfo, asyncContext);
}

void QueryCurrentOAExecuteCB(napi_env env, void *data)
{
    CurrentOAAsyncContext *asyncContext = reinterpret_cast<CurrentOAAsyncContext *>(data);
    asyncContext->errCode = OsAccountManager::QueryCurrentOsAccount(asyncContext->osAccountInfos);
    // for compatibility
    if ((!asyncContext->throwErr) && (asyncContext->errCode == ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED)) {
        asyncContext->errCode = ERR_OSACCOUNT_KIT_QUERY_CURRENT_OS_ACCOUNT_ERROR;
    }
    asyncContext->status = (asyncContext->errCode == 0) ? napi_ok : napi_generic_failure;
}

void QueryCurrentOACallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    CurrentOAAsyncContext *asyncContext = reinterpret_cast<CurrentOAAsyncContext *>(data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->status == napi_ok) {
        errJs = GenerateBusinessSuccess(env, asyncContext->throwErr);
        GetOACBInfoToJs(env, asyncContext->osAccountInfos, dataJs);
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode, asyncContext->throwErr);
        if (asyncContext->throwErr) {
            napi_get_null(env, &dataJs);
        } else {
            GetOACBInfoToJs(env, asyncContext->osAccountInfos, dataJs);
        }
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
    napi_delete_async_work(env, asyncContext->work);
    delete asyncContext;
    asyncContext = nullptr;
}

bool ParseParaGetIdByUid(napi_env env, napi_callback_info cbInfo, GetIdByUidAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc == ARGS_SIZE_TWO) {
        if (!GetCallbackProperty(env, argv[argc - 1], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            std::string errMsg = "The type of arg " + std::to_string(argc) + " must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
    }

    if (!GetIntProperty(env, argv[PARAMZERO], asyncContext->uid)) {
        ACCOUNT_LOGE("Get uid failed");
        std::string errMsg = "The type of arg 1 must be number";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    return true;
}

bool ParseParaGetIdByDomain(napi_env env, napi_callback_info cbInfo, GetIdByDomainAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc == ARGS_SIZE_TWO) {
        if (!GetCallbackProperty(env, argv[argc - 1], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            std::string errMsg = "The type of arg " + std::to_string(argc) + " must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
    }

    if (!GetStringPropertyByKey(env, argv[PARAMZERO], "domain", asyncContext->domainInfo.domain_)) {
        ACCOUNT_LOGE("Get domainInfo's domain failed");
        std::string errMsg = "The type of arg 1's domain must be string";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    if (!GetStringPropertyByKey(env, argv[PARAMZERO], "accountName", asyncContext->domainInfo.accountName_)) {
        ACCOUNT_LOGE("Get domainInfo's accountName failed");
        std::string errMsg = "The type of arg 1's accountName must be string";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }

    return true;
}

void GetIdByUidExecuteCB(napi_env env, void *data)
{
    GetIdByUidAsyncContext *asyncContext = reinterpret_cast<GetIdByUidAsyncContext *>(data);
    asyncContext->errCode = OsAccountManager::GetOsAccountLocalIdFromUid(asyncContext->uid, asyncContext->id);
    ACCOUNT_LOGD("error code is %{public}d", asyncContext->errCode);
    asyncContext->status = (asyncContext->errCode == 0) ? napi_ok : napi_generic_failure;
}

void GetBundleIdByUidExecuteCB(napi_env env, void *data)
{
    GetIdByUidAsyncContext *asyncContext = reinterpret_cast<GetIdByUidAsyncContext *>(data);
    asyncContext->errCode = OsAccountManager::GetBundleIdFromUid(asyncContext->uid, asyncContext->id);
    ACCOUNT_LOGD("error code is %{public}d", asyncContext->errCode);
    asyncContext->status = (asyncContext->errCode == 0) ? napi_ok : napi_generic_failure;
}

void GetIdByDomainExecuteCB(napi_env env, void *data)
{
    GetIdByDomainAsyncContext *asyncContext = reinterpret_cast<GetIdByDomainAsyncContext *>(data);
    asyncContext->errCode = OsAccountManager::GetOsAccountLocalIdFromDomain(
        asyncContext->domainInfo, asyncContext->id);
    ACCOUNT_LOGD("error code is %{public}d", asyncContext->errCode);
    asyncContext->status = (asyncContext->errCode == 0) ? napi_ok : napi_generic_failure;
}

void GetIdByUidCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGD("napi_create_async_work complete");
    GetIdByUidAsyncContext *asyncContext = reinterpret_cast<GetIdByUidAsyncContext *>(data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->status == napi_ok) {
        errJs = GenerateBusinessSuccess(env, asyncContext->throwErr);
        napi_create_int32(env, asyncContext->id, &dataJs);
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode, asyncContext->throwErr);
        if (asyncContext->throwErr) {
            napi_get_null(env, &dataJs);
        } else {
            napi_create_int32(env, asyncContext->id, &dataJs);
        }
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
    napi_delete_async_work(env, asyncContext->work);
    delete asyncContext;
    asyncContext = nullptr;
}

void GetBundleIdByUidCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGD("napi_create_async_work complete");
    GetIdByUidAsyncContext *asyncContext = reinterpret_cast<GetIdByUidAsyncContext *>(data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->status == napi_ok) {
        napi_get_null(env, &errJs);
        napi_create_int32(env, asyncContext->id, &dataJs);
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode, asyncContext->throwErr);
        napi_get_null(env, &dataJs);
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
    napi_delete_async_work(env, asyncContext->work);
    delete asyncContext;
    asyncContext = nullptr;
}

void GetIdByDomainCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGD("napi_create_async_work complete");
    GetIdByDomainAsyncContext *asyncContext = reinterpret_cast<GetIdByDomainAsyncContext *>(data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->status == napi_ok) {
        errJs = GenerateBusinessSuccess(env, asyncContext->throwErr);
        napi_create_int32(env, asyncContext->id, &dataJs);
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode, asyncContext->throwErr);
        if (asyncContext->throwErr) {
            napi_get_null(env, &dataJs);
        } else {
            napi_create_int32(env, asyncContext->id, &dataJs);
        }
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
    napi_delete_async_work(env, asyncContext->work);
    delete asyncContext;
    asyncContext = nullptr;
}

bool ParseParaSetPhoto(napi_env env, napi_callback_info cbInfo, SetOAPhotoAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc == ARGS_SIZE_THREE) {
        if (!GetCallbackProperty(env, argv[argc - 1], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            std::string errMsg = "The type of arg " + std::to_string(argc) + " must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
    }

    if (!GetIntProperty(env, argv[PARAMZERO], asyncContext->id)) {
        ACCOUNT_LOGE("Get id failed");
        std::string errMsg = "The type of arg 1 must be number";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    if (!GetStringProperty(env, argv[PARAMONE], asyncContext->photo)) {
        ACCOUNT_LOGE("Get photo failed");
        std::string errMsg = "The type of arg 2 must be string";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }

    return true;
}

void SetPhotoExecuteCB(napi_env env, void *data)
{
    SetOAPhotoAsyncContext *asyncContext = reinterpret_cast<SetOAPhotoAsyncContext *>(data);
    asyncContext->errCode = OsAccountManager::SetOsAccountProfilePhoto(asyncContext->id, asyncContext->photo);
    ACCOUNT_LOGD("error code is %{public}d", asyncContext->errCode);
    asyncContext->status = (asyncContext->errCode == 0) ? napi_ok : napi_generic_failure;
}

void SetPhotoCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGD("napi_create_async_work complete");
    SetOAPhotoAsyncContext *asyncContext = reinterpret_cast<SetOAPhotoAsyncContext *>(data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->status == napi_ok) {
        napi_get_null(env, &errJs);
        napi_get_null(env, &dataJs);
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode, asyncContext->throwErr);
        napi_get_null(env, &dataJs);
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
    napi_delete_async_work(env, asyncContext->work);
    delete asyncContext;
    asyncContext = nullptr;
}

bool ParseParaQueryMaxNum(napi_env env, napi_callback_info cbInfo, QueryMaxNumAsyncContext *asyncContext)
{
    return ParseOneParaContext(env, cbInfo, asyncContext);
}

void QueryMaxNumExecuteCB(napi_env env, void *data)
{
    QueryMaxNumAsyncContext *asyncContext = reinterpret_cast<QueryMaxNumAsyncContext *>(data);
    asyncContext->errCode = OsAccountManager::QueryMaxOsAccountNumber(asyncContext->maxOsAccountNumber);
    ACCOUNT_LOGD("error code is %{public}d", asyncContext->errCode);
    asyncContext->status = (asyncContext->errCode == 0) ? napi_ok : napi_generic_failure;
}

void QueryMaxNumCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGD("napi_create_async_work complete");
    QueryMaxNumAsyncContext *asyncContext = reinterpret_cast<QueryMaxNumAsyncContext *>(data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->status == napi_ok) {
        napi_get_null(env, &errJs);
        napi_create_int32(env, asyncContext->maxOsAccountNumber, &dataJs);
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode, asyncContext->throwErr);
        napi_get_null(env, &dataJs);
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
    napi_delete_async_work(env, asyncContext->work);
    delete asyncContext;
    asyncContext = nullptr;
}

bool ParseParaIsActived(napi_env env, napi_callback_info cbInfo, IsActivedAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc == ARGS_SIZE_TWO) {
        if (!GetCallbackProperty(env, argv[argc - 1], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            std::string errMsg = "The type of arg " + std::to_string(argc) + " must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
    }

    if (!GetIntProperty(env, argv[PARAMZERO], asyncContext->id)) {
        ACCOUNT_LOGE("Get id failed");
        std::string errMsg = "The type of arg 1 must be number";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }

    return true;
}

void IsActivedExecuteCB(napi_env env, void *data)
{
    IsActivedAsyncContext *asyncContext = reinterpret_cast<IsActivedAsyncContext *>(data);
    asyncContext->errCode = OsAccountManager::IsOsAccountActived(asyncContext->id, asyncContext->isOsAccountActived);
    // for compatibility
    if ((!asyncContext->throwErr) && (asyncContext->errCode == ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED)) {
        asyncContext->errCode = ERR_OSACCOUNT_KIT_IS_OS_ACCOUNT_ACTIVED_ERROR;
    }
    asyncContext->status = (asyncContext->errCode == 0) ? napi_ok : napi_generic_failure;
}

void IsActivedCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGD("napi_create_async_work complete");
    IsActivedAsyncContext *asyncContext = reinterpret_cast<IsActivedAsyncContext *>(data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->status == napi_ok) {
        errJs = GenerateBusinessSuccess(env, asyncContext->throwErr);
        napi_get_boolean(env, asyncContext->isOsAccountActived, &dataJs);
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode, asyncContext->throwErr);
        if (asyncContext->throwErr) {
            napi_get_null(env, &dataJs);
        } else {
            napi_get_boolean(env, asyncContext->isOsAccountActived, &dataJs);
        }
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
    napi_delete_async_work(env, asyncContext->work);
    delete asyncContext;
    asyncContext = nullptr;
}

bool ParseParaIsEnable(napi_env env, napi_callback_info cbInfo, IsConEnableAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc == ARGS_SIZE_THREE) {
        if (!GetCallbackProperty(env, argv[argc - 1], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            std::string errMsg = "The type of arg " + std::to_string(argc) + " must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
    }

    if (!GetIntProperty(env, argv[PARAMZERO], asyncContext->id)) {
        ACCOUNT_LOGE("Get id failed");
        std::string errMsg = "The type of arg 1 must be number";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    if (!GetStringProperty(env, argv[PARAMONE], asyncContext->constraint)) {
        ACCOUNT_LOGE("Get constraint failed");
        std::string errMsg = "The type of arg 2 must be string";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    return true;
}

void IsEnableExecuteCB(napi_env env, void *data)
{
    IsConEnableAsyncContext *asyncContext = reinterpret_cast<IsConEnableAsyncContext *>(data);
    if (asyncContext->throwErr) {
        asyncContext->errCode = OsAccountManager::CheckOsAccountConstraintEnabled(asyncContext->id,
            asyncContext->constraint, asyncContext->isConsEnable);
    } else {
        asyncContext->errCode = OsAccountManager::IsOsAccountConstraintEnable(asyncContext->id,
            asyncContext->constraint, asyncContext->isConsEnable);
    }

    // for compatibility
    if ((!asyncContext->throwErr) && (asyncContext->errCode == ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED)) {
        asyncContext->errCode = ERR_OSACCOUNT_KIT_IS_OS_ACCOUNT_CONSTRAINT_ENABLE_ERROR;
    }
    asyncContext->status = (asyncContext->errCode == 0) ? napi_ok : napi_generic_failure;
}

void IsEnableCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGD("napi_create_async_work complete");
    IsConEnableAsyncContext *asyncContext = reinterpret_cast<IsConEnableAsyncContext *>(data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->status == napi_ok) {
        errJs = GenerateBusinessSuccess(env, asyncContext->throwErr);
        napi_get_boolean(env, asyncContext->isConsEnable, &dataJs);
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode, asyncContext->throwErr);
        if (asyncContext->throwErr) {
            napi_get_null(env, &dataJs);
        } else {
            napi_get_boolean(env, asyncContext->isConsEnable, &dataJs);
        }
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
    napi_delete_async_work(env, asyncContext->work);
    delete asyncContext;
    asyncContext = nullptr;
}

bool ParseParaGetType(napi_env env, napi_callback_info cbInfo, GetTypeAsyncContext *asyncContext)
{
    return ParseOneParaContext(env, cbInfo, asyncContext);
}

void GetTypeExecuteCB(napi_env env, void *data)
{
    GetTypeAsyncContext *asyncContext = reinterpret_cast<GetTypeAsyncContext *>(data);
    asyncContext->errCode = OsAccountManager::GetOsAccountTypeFromProcess(asyncContext->type);
    ACCOUNT_LOGD("error code is %{public}d", asyncContext->errCode);
    asyncContext->status = (asyncContext->errCode == 0) ? napi_ok : napi_generic_failure;
}

void GetTypeCompletedCB(napi_env env, napi_status status, void *data)
{
    GetTypeAsyncContext *asyncContext = reinterpret_cast<GetTypeAsyncContext *>(data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->status == napi_ok) {
        errJs = GenerateBusinessSuccess(env, asyncContext->throwErr);
        int cType = static_cast<int>(asyncContext->type);
        napi_create_int32(env, cType, &dataJs);
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode, asyncContext->throwErr);
        napi_get_null(env, &dataJs);
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
    napi_delete_async_work(env, asyncContext->work);
    delete asyncContext;
    asyncContext = nullptr;
}

bool ParseParaIsMultiEn(napi_env env, napi_callback_info cbInfo, IsMultiEnAsyncContext *asyncContext)
{
    return ParseOneParaContext(env, cbInfo, asyncContext);
}

void IsMultiEnExecuteCB(napi_env env, void *data)
{
    IsMultiEnAsyncContext *asyncContext = reinterpret_cast<IsMultiEnAsyncContext *>(data);
    asyncContext->errCode = OsAccountManager::IsMultiOsAccountEnable(asyncContext->isMultiOAEnable);
    ACCOUNT_LOGD("error code is %{public}d", asyncContext->errCode);
    asyncContext->status = (asyncContext->errCode == 0) ? napi_ok : napi_generic_failure;
}

void IsMultiEnCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGD("napi_create_async_work complete");
    IsMultiEnAsyncContext *asyncContext = reinterpret_cast<IsMultiEnAsyncContext *>(data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->status == napi_ok) {
        errJs = GenerateBusinessSuccess(env, asyncContext->throwErr);
        napi_get_boolean(env, asyncContext->isMultiOAEnable, &dataJs);
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode, asyncContext->throwErr);
        if (asyncContext->throwErr) {
            napi_get_null(env, &dataJs);
        } else {
            napi_get_boolean(env, asyncContext->isMultiOAEnable, &dataJs);
        }
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
    napi_delete_async_work(env, asyncContext->work);
    delete asyncContext;
    asyncContext = nullptr;
}

bool ParseParaIsVerified(napi_env env, napi_callback_info cbInfo, IsVerifiedAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    if (argc == 0) {
        return true;
    }
    if (argc == ARGS_SIZE_ONE) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[PARAMZERO], &valueType);
        if (valueType == napi_number) {
            if (!GetIntProperty(env, argv[PARAMZERO], asyncContext->id)) {
                ACCOUNT_LOGE("Get id failed");
                std::string errMsg = "The type of arg 1 must be number";
                AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
                return false;
            }
        } else if (valueType == napi_function) {
            if (!GetCallbackProperty(env, argv[PARAMZERO], asyncContext->callbackRef, 1)) {
                ACCOUNT_LOGE("Get callbackRef failed");
                std::string errMsg = "The type of arg 1 must be function";
                AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
                return false;
            }
        } else {
            ACCOUNT_LOGE("Wrong arg type, expected number or function");
            std::string errMsg = "The type of arg 1 must be number or function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
        return true;
    }
    if (argc == ARGS_SIZE_TWO) {
        if (!GetCallbackProperty(env, argv[argc - 1], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            std::string errMsg = "The type of arg " + std::to_string(argc) + " must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
        if (!GetIntProperty(env, argv[PARAMZERO], asyncContext->id)) {
            ACCOUNT_LOGE("Get id failed");
            std::string errMsg = "The type of arg 1 must be number";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
    }
    return true;
}

void IsVerifiedExecuteCB(napi_env env, void *data)
{
    IsVerifiedAsyncContext *asyncContext = reinterpret_cast<IsVerifiedAsyncContext *>(data);
    if (asyncContext->id < 0) {
        asyncContext->errCode = OsAccountManager::IsCurrentOsAccountVerified(asyncContext->isTestOA);
    } else {
        asyncContext->errCode = OsAccountManager::IsOsAccountVerified(asyncContext->id, asyncContext->isTestOA);
    }
    // for compatibility
    if ((!asyncContext->throwErr) && (asyncContext->errCode == ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED)) {
        asyncContext->errCode = ERR_OSACCOUNT_KIT_IS_OS_ACCOUNT_VERIFIED_ERROR;
    }
    asyncContext->status = (asyncContext->errCode == 0) ? napi_ok : napi_generic_failure;
}

void IsVerifiedCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGD("napi_create_async_work complete");
    IsVerifiedAsyncContext *asyncContext = reinterpret_cast<IsVerifiedAsyncContext *>(data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->status == napi_ok) {
        errJs = GenerateBusinessSuccess(env, asyncContext->throwErr);
        napi_get_boolean(env, asyncContext->isTestOA, &dataJs);
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode, asyncContext->throwErr);
        if (asyncContext->throwErr) {
            napi_get_null(env, &dataJs);
        } else {
            napi_get_boolean(env, asyncContext->isTestOA, &dataJs);
        }
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
    napi_delete_async_work(env, asyncContext->work);
    delete asyncContext;
    asyncContext = nullptr;
}

bool ParseParaSerialNumId(napi_env env, napi_callback_info cbInfo, GetSerialNumIdCBInfo *asyncContext)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc == ARGS_SIZE_TWO) {
        if (!GetCallbackProperty(env, argv[argc - 1], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            std::string errMsg = "The type of arg " + std::to_string(argc) + " must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
    }
    if (!GetLongIntProperty(env, argv[PARAMZERO], asyncContext->serialNumber)) {
        ACCOUNT_LOGE("Get serialNumber failed");
        std::string errMsg = "The type of arg 1 must be number";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }

    return true;
}

void SerialNumIdExecuteCB(napi_env env, void *data)
{
    GetSerialNumIdCBInfo *asyncContext = reinterpret_cast<GetSerialNumIdCBInfo *>(data);
    asyncContext->errCode =
        OsAccountManager::GetOsAccountLocalIdBySerialNumber(asyncContext->serialNumber, asyncContext->id);
    asyncContext->status = (asyncContext->errCode == 0) ? napi_ok : napi_generic_failure;
}

void SerialNumIdCompletedCB(napi_env env, napi_status status, void *data)
{
    GetSerialNumIdCBInfo *asyncContext = reinterpret_cast<GetSerialNumIdCBInfo *>(data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->status == napi_ok) {
        errJs = GenerateBusinessSuccess(env, asyncContext->throwErr);
        napi_create_int32(env, asyncContext->id, &dataJs);
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode, asyncContext->throwErr);
        if (asyncContext->throwErr) {
            napi_get_null(env, &dataJs);
        } else {
            napi_create_int32(env, asyncContext->id, &dataJs);
        }
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
    napi_delete_async_work(env, asyncContext->work);
    delete asyncContext;
    asyncContext = nullptr;
}

bool ParseParaGetSerialNum(napi_env env, napi_callback_info cbInfo, GetSerialNumForOAInfo *asyncContext)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc == ARGS_SIZE_TWO) {
        if (!GetCallbackProperty(env, argv[argc - 1], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            std::string errMsg = "The type of arg " + std::to_string(argc) + " must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
    }

    if (!GetIntProperty(env, argv[PARAMZERO], asyncContext->id)) {
        ACCOUNT_LOGE("Get id failed");
        std::string errMsg = "The type of arg 1 must be number";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    return true;
}

void GetSerialNumExecuteCB(napi_env env, void *data)
{
    GetSerialNumForOAInfo *asyncContext = reinterpret_cast<GetSerialNumForOAInfo *>(data);
    asyncContext->errCode =
        OsAccountManager::GetSerialNumberByOsAccountLocalId(asyncContext->id, asyncContext->serialNum);
    ACCOUNT_LOGD("error code is %{public}d", asyncContext->errCode);
    asyncContext->status = (asyncContext->errCode == 0) ? napi_ok : napi_generic_failure;
}

void GetSerialNumCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGD("napi_create_async_work complete");
    GetSerialNumForOAInfo *asyncContext = reinterpret_cast<GetSerialNumForOAInfo *>(data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->status == napi_ok) {
        errJs = GenerateBusinessSuccess(env, asyncContext->throwErr);
        napi_create_int64(env, asyncContext->serialNum, &dataJs);
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode, asyncContext->throwErr);
        if (asyncContext->throwErr) {
            napi_get_null(env, &dataJs);
        } else {
            napi_create_int64(env, asyncContext->serialNum, &dataJs);
        }
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
    napi_delete_async_work(env, asyncContext->work);
    delete asyncContext;
    asyncContext = nullptr;
}

bool ParseParaIsTestOA(napi_env env, napi_callback_info cbInfo, IsTestOAInfo *asyncContext)
{
    return ParseOneParaContext(env, cbInfo, asyncContext);
}

bool ParseParaIsMainOA(napi_env env, napi_callback_info cbInfo, IsMainOAInfo *asyncContext)
{
    return ParseOneParaContext(env, cbInfo, asyncContext);
}

bool ParseParaToSubscriber(const napi_env &env, napi_callback_info cbInfo, SubscribeCBInfo *asyncContext,
    napi_value *thisVar)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_get_cb_info(env, cbInfo, &argc, argv, thisVar, NULL);
    if (argc < ARGS_SIZE_THREE) {
        ACCOUNT_LOGE("The arg number less than 3 characters");
        std::string errMsg = "The arg number must be at least 3 characters";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    if (argc == ARGS_SIZE_THREE) {
        if (!GetCallbackProperty(env, argv[argc - 1], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            std::string errMsg = "The type of arg " + std::to_string(argc) + " must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
    }

    // argv[0] type: 'activate' | 'activating'
    std::string type;
    if (!GetStringProperty(env, argv[PARAMZERO], type)) {
        ACCOUNT_LOGE("Get type failed");
        std::string errMsg = "The type of arg 1 must be string";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    if (type == "activate") {
        asyncContext->osSubscribeType = OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVED;
    } else if (type == "activating") {
        asyncContext->osSubscribeType = OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATING;
    } else {
        ACCOUNT_LOGE("Get type failed, type is invalid");
        std::string errMsg = "The value of arg 1 must be 'activate' or 'activating'";
        AccountNapiThrow(env, ERR_JS_INVALID_PARAMETER, errMsg, asyncContext->throwErr);
        return false;
    }

    // argv[1] name: string
    if (!GetStringProperty(env, argv[PARAMONE], asyncContext->name)) {
        ACCOUNT_LOGE("Get name failed");
        std::string errMsg = "The type of arg 2 must be string";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    size_t nameSize = asyncContext->name.size();
    if (nameSize == 0 || nameSize > MAX_SUBSCRIBER_NAME_LEN) {
        ACCOUNT_LOGE("Subscriber name size %{public}zu is invalid.", nameSize);
        std::string errMsg = "The length of arg 2 is invalid";
        AccountNapiThrow(env, ERR_JS_INVALID_PARAMETER, errMsg, asyncContext->throwErr);
        return false;
    }

    return true;
}

void SubscribeExecuteCB(napi_env env, void *data)
{
    SubscribeCBInfo *asyncContext = reinterpret_cast<SubscribeCBInfo *>(data);
    asyncContext->subscriber->SetEnv(env);
    asyncContext->subscriber->SetCallbackRef(asyncContext->callbackRef);
    int errCode = OsAccountManager::SubscribeOsAccount(asyncContext->subscriber);
    ACCOUNT_LOGD("error code is %{public}d", errCode);
}

void SubscribeCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGD("napi_create_async_work complete.");
    SubscribeCBInfo *asyncContext = reinterpret_cast<SubscribeCBInfo *>(data);
    napi_delete_async_work(env, asyncContext->work);
}

bool ParseParaToUnsubscriber(const napi_env &env, napi_callback_info cbInfo, UnsubscribeCBInfo *asyncContext,
    napi_value *thisVar)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_get_cb_info(env, cbInfo, &argc, argv, thisVar, NULL);
    if (argc < ARGS_SIZE_TWO) {
        ACCOUNT_LOGE("The arg number less than 2 characters");
        std::string errMsg = "The arg number must be at least 2 characters";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    if (argc == ARGS_SIZE_THREE) {
        if (!GetCallbackProperty(env, argv[argc - 1], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            std::string errMsg = "The type of arg " + std::to_string(argc) + " must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
    }

    // argv[0] type: 'activate' | 'activating'
    std::string type;
    if (!GetStringProperty(env, argv[PARAMZERO], type)) {
        std::string errMsg = "The type of arg 1 must be string";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    if (type == "activate") {
        asyncContext->osSubscribeType = OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVED;
    } else if (type == "activating") {
        asyncContext->osSubscribeType = OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATING;
    } else {
        ACCOUNT_LOGE("Get type fail, type is invalid");
        std::string errMsg = "The value of arg 1 must be 'activate' or 'activating'";
        AccountNapiThrow(env, ERR_JS_INVALID_PARAMETER, errMsg, asyncContext->throwErr);
        return false;
    }

    // argv[1] name: string
    if (!GetStringProperty(env, argv[PARAMONE], asyncContext->name)) {
        ACCOUNT_LOGE("Get name failed");
        std::string errMsg = "The type of arg 2 must be string";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    size_t nameSize = asyncContext->name.size();
    if (nameSize == 0 || nameSize > MAX_SUBSCRIBER_NAME_LEN) {
        ACCOUNT_LOGE("Subscriber name size %{public}zu is invalid.", nameSize);
        std::string errMsg = "The length of arg 2 is invalid";
        AccountNapiThrow(env, ERR_JS_INVALID_PARAMETER, errMsg, asyncContext->throwErr);
        return false;
    }

    return true;
}
}  // namespace AccountJsKit
}  // namespace OHOS
