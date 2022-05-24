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

#include "napi_os_account.h"

namespace OHOS {
namespace AccountJsKit {
napi_value WrapVoidToJS(napi_env env)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    return result;
}

int GetIntProperty(napi_env env, napi_value obj)
{
    ACCOUNT_LOGI("enter");
    int intTypeToJs = 0;
    if (napi_get_value_int32(env, obj, &intTypeToJs) != napi_ok) {
    }

    return intTypeToJs;
}

int64_t GetLongIntProperty(napi_env env, napi_value obj)
{
    ACCOUNT_LOGI("enter");
    int64_t intTypeToJs = 0;
    if (napi_get_value_int64(env, obj, &intTypeToJs) != napi_ok) {
    }

    return intTypeToJs;
}

napi_value GetErrorCodeValue(napi_env env, int errCode)
{
    ACCOUNT_LOGI("enter");
    napi_value jsObject = nullptr;
    napi_value jsValue = nullptr;
    NAPI_CALL(env, napi_create_int32(env, errCode, &jsValue));
    NAPI_CALL(env, napi_create_object(env, &jsObject));
    NAPI_CALL(env, napi_set_named_property(env, jsObject, "code", jsValue));
    return jsObject;
}

std::string GetStringProperty(napi_env env, napi_value obj)
{
    ACCOUNT_LOGI("enter");
    char propValue[MAX_VALUE_LEN] = {0};
    size_t propLen;
    if (napi_get_value_string_utf8(env, obj, propValue, MAX_VALUE_LEN, &propLen) != napi_ok) {
        ACCOUNT_LOGI("Can not get string param from argv");
    }

    return std::string(propValue);
}

napi_value ParseParaQueryOAByIdCB(napi_env env, napi_callback_info cbInfo, QueryOAByIdAsyncContext *queryOAByIdCB)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == 0 && valueType == napi_number) {
            queryOAByIdCB->id = GetIntProperty(env, argv[i]);
        } else if (valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &queryOAByIdCB->callbackRef);
            break;
        } else {
            ACCOUNT_LOGE("Type matching failed");
            return nullptr;
        }
    }
    return WrapVoidToJS(env);
}

void QueryOAByIdExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    QueryOAByIdAsyncContext *queryOAByIdCB = reinterpret_cast<QueryOAByIdAsyncContext *>(data);
    queryOAByIdCB->errCode = OsAccountManager::QueryOsAccountById(queryOAByIdCB->id, queryOAByIdCB->osAccountInfos);
    ACCOUNT_LOGI("errcode is %{public}d", queryOAByIdCB->errCode);
    queryOAByIdCB->status = (queryOAByIdCB->errCode == 0) ? napi_ok : napi_generic_failure;
}

void QueryOAByIdCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    QueryOAByIdAsyncContext *queryOAByIdCB = reinterpret_cast<QueryOAByIdAsyncContext *>(data);
    napi_value queryResult[RESULT_COUNT] = {0};
    queryResult[PARAMZERO] = GetErrorCodeValue(env, queryOAByIdCB->errCode);
    napi_create_object(env, &queryResult[PARAMONE]);
    GetOACBInfoToJs(env, queryOAByIdCB->osAccountInfos, queryResult[PARAMONE]);
    CBOrPromiseToQueryOAById(env, queryOAByIdCB, queryResult[PARAMZERO], queryResult[PARAMONE]);
    napi_delete_async_work(env, queryOAByIdCB->work);
    delete queryOAByIdCB;
    queryOAByIdCB = nullptr;
}

void GetOACBInfoToJs(napi_env env, OsAccountInfo &info, napi_value objOAInfo)
{
    ACCOUNT_LOGI("enter");
    // localId
    int id = info.GetLocalId();
    napi_value idToJs = nullptr;
    napi_create_int32(env, id, &idToJs);
    napi_set_named_property(env, objOAInfo, "localId", idToJs);

    // localName
    std::string name = info.GetLocalName();
    napi_value nameToJs = nullptr;
    napi_create_string_utf8(env, name.c_str(), NAPI_AUTO_LENGTH, &nameToJs);
    napi_set_named_property(env, objOAInfo, "localName", nameToJs);

    // type
    int type = static_cast<int>(info.GetType());
    napi_value typeToJsObj = nullptr;
    napi_value valToJs = nullptr;
    napi_create_object(env, &typeToJsObj);
    napi_create_int32(env, type, &valToJs);
    switch (type) {
        case PARAMZERO:
            napi_set_named_property(env, typeToJsObj, "ADMIN", valToJs);
            break;
        case PARAMONE:
            napi_set_named_property(env, typeToJsObj, "NORMAL", valToJs);
            break;
        case PARAMTWO:
            napi_set_named_property(env, typeToJsObj, "GUEST", valToJs);
            break;
        default:
            ACCOUNT_LOGI("cType %{public}d is an invalid value", type);
            break;
    }
    napi_set_named_property(env, objOAInfo, "type", typeToJsObj);

    // constraints
    std::vector<std::string> constraints = info.GetConstraints();
    napi_value constraintsToJs = nullptr;
    napi_create_array(env, &constraintsToJs);
    MakeArrayToJs(env, constraints, constraintsToJs);
    napi_set_named_property(env, objOAInfo, "constraints", constraintsToJs);

    // isVerified
    bool isVerified = info.GetIsVerified();
    napi_value isVerifiedToJs = nullptr;
    napi_get_boolean(env, isVerified, &isVerifiedToJs);
    napi_set_named_property(env, objOAInfo, "isVerified", isVerifiedToJs);

    // photo
    std::string photo = info.GetPhoto();
    napi_value photoToJs = nullptr;
    napi_create_string_utf8(env, photo.c_str(), NAPI_AUTO_LENGTH, &photoToJs);
    napi_set_named_property(env, objOAInfo, "photo", photoToJs);

    // createTime
    int64_t createTime = info.GetCreateTime();
    napi_value createTimeToJs = nullptr;
    napi_create_int64(env, createTime, &createTimeToJs);
    napi_set_named_property(env, objOAInfo, "createTime", createTimeToJs);

    // lastLoginTime
    int64_t lastLoginTime = info.GetLastLoginTime();
    napi_value lastLoginTimeToJs = nullptr;
    napi_create_int64(env, lastLoginTime, &lastLoginTimeToJs);
    napi_set_named_property(env, objOAInfo, "lastLoginTime", lastLoginTimeToJs);

    // serialNumber
    int64_t serialNumber = info.GetSerialNumber();
    napi_value serialNumberToJs = nullptr;
    napi_create_int64(env, serialNumber, &serialNumberToJs);
    napi_set_named_property(env, objOAInfo, "serialNumber", serialNumberToJs);

    // isActived
    bool isActived = info.GetIsActived();
    napi_value isActivedToJs = nullptr;
    napi_get_boolean(env, isActived, &isActivedToJs);
    napi_set_named_property(env, objOAInfo, "isActived", isActivedToJs);

    // isCreateCompleted
    bool isCreateCompleted = info.GetIsCreateCompleted();
    napi_value isCreateCompletedToJs = nullptr;
    napi_get_boolean(env, isCreateCompleted, &isCreateCompletedToJs);
    napi_set_named_property(env, objOAInfo, "isCreateCompleted", isCreateCompletedToJs);

    // distributedInfo: distributedAccount.DistributedInfo
    napi_value dbInfoToJs = nullptr;
    napi_value value = nullptr;
    napi_create_object(env, &dbInfoToJs);
    std::pair<bool, OhosAccountInfo> dbAccountInfo = OhosAccountKits::GetInstance().QueryOhosAccountInfo();
    if (dbAccountInfo.first) {
        // name
        napi_create_string_utf8(env, dbAccountInfo.second.name_.c_str(), dbAccountInfo.second.name_.size(), &value);
        napi_set_named_property(env, dbInfoToJs, "name", value);

        // id
        napi_create_string_utf8(env, dbAccountInfo.second.uid_.c_str(), dbAccountInfo.second.uid_.size(), &value);
        napi_set_named_property(env, dbInfoToJs, "id", value);

        // event
        std::string event = "";
        napi_create_string_utf8(env, event.c_str(), event.size(), &value);
        napi_set_named_property(env, dbInfoToJs, "event", value);

        // scalableData
        napi_value scalable = nullptr;
        napi_create_object(env, &scalable);
        napi_set_named_property(env, dbInfoToJs, "scalableData", scalable);
    } else {
        napi_get_undefined(env, &dbInfoToJs);
    }
    napi_set_named_property(env, objOAInfo, "distributedInfo", dbInfoToJs);

    // domainInfo: domainInfo.DomainAccountInfo
    dbInfoToJs = nullptr;
    value = nullptr;
    napi_create_object(env, &dbInfoToJs);

    DomainAccountInfo domainInfo;
    info.GetDomainInfo(domainInfo);

    // domain
    napi_create_string_utf8(env, domainInfo.domain_.c_str(), domainInfo.domain_.size(), &value);
    napi_set_named_property(env, dbInfoToJs, "domain", value);

    // domain accountName
    napi_create_string_utf8(env, domainInfo.accountName_.c_str(), domainInfo.accountName_.size(), &value);
    napi_set_named_property(env, dbInfoToJs, "accountName", value);
    napi_set_named_property(env, objOAInfo, "domainInfo", dbInfoToJs);
}

void MakeArrayToJs(napi_env env, const std::vector<std::string> &constraints, napi_value jsArray)
{
    ACCOUNT_LOGI("enter");

    uint32_t index = 0;

    for (auto item : constraints) {
        napi_value constraint = nullptr;
        napi_create_string_utf8(env, item.c_str(), NAPI_AUTO_LENGTH, &constraint);
        napi_set_element(env, jsArray, index, constraint);
        index++;
    }
}

void CBOrPromiseToQueryOAById(
    napi_env env, const QueryOAByIdAsyncContext *queryOAByIdCB, napi_value err, napi_value data)
{
    ACCOUNT_LOGI("enter");
    napi_value args[RESULT_COUNT] = {err, data};
    if (queryOAByIdCB->deferred) {
        ACCOUNT_LOGI("Promise");
        if (queryOAByIdCB->status == napi_ok) {
            napi_resolve_deferred(env, queryOAByIdCB->deferred, args[1]);
        } else {
            napi_reject_deferred(env, queryOAByIdCB->deferred, args[0]);
        }
    } else {
        ACCOUNT_LOGI("Callback");
        napi_value callback = nullptr;
        napi_get_reference_value(env, queryOAByIdCB->callbackRef, &callback);
        napi_value returnVal = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, &args[0], &returnVal);
        if (queryOAByIdCB->callbackRef != nullptr) {
            napi_delete_reference(env, queryOAByIdCB->callbackRef);
        }
    }
}

napi_value ParseParaRemoveOACB(napi_env env, napi_callback_info cbInfo, RemoveOAAsyncContext *removeOACB)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == 0 && valueType == napi_number) {
            removeOACB->id = GetIntProperty(env, argv[i]);
        } else if (valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &removeOACB->callbackRef);
            break;
        } else {
            ACCOUNT_LOGE("Type matching failed");
            return nullptr;
        }
    }
    return WrapVoidToJS(env);
}

void RemoveOAExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    RemoveOAAsyncContext *removeOACB = reinterpret_cast<RemoveOAAsyncContext *>(data);
    removeOACB->errCode = OsAccountManager::RemoveOsAccount(removeOACB->id);
    ACCOUNT_LOGI("errcode is %{public}d", removeOACB->errCode);
    removeOACB->status = (removeOACB->errCode == 0) ? napi_ok : napi_generic_failure;
}

void RemoveOACallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    RemoveOAAsyncContext *removeOACB = reinterpret_cast<RemoveOAAsyncContext *>(data);
    napi_value rmResult[RESULT_COUNT] = {0};
    rmResult[PARAMZERO] = GetErrorCodeValue(env, removeOACB->errCode);
    napi_get_undefined(env, &rmResult[PARAMONE]);
    CBOrPromiseToRemoveOA(env, removeOACB, rmResult[PARAMZERO], rmResult[PARAMONE]);
    napi_delete_async_work(env, removeOACB->work);
    delete removeOACB;
    removeOACB = nullptr;
}

void CBOrPromiseToRemoveOA(napi_env env, const RemoveOAAsyncContext *removeOACB, napi_value err, napi_value data)
{
    ACCOUNT_LOGI("enter");
    napi_value args[RESULT_COUNT] = {err, data};
    if (removeOACB->deferred) {
        ACCOUNT_LOGI("Promise");
        if (removeOACB->status == napi_ok) {
            napi_resolve_deferred(env, removeOACB->deferred, args[1]);
        } else {
            napi_reject_deferred(env, removeOACB->deferred, args[0]);
        }
    } else {
        ACCOUNT_LOGI("Callback");
        napi_value callback = nullptr;
        napi_get_reference_value(env, removeOACB->callbackRef, &callback);
        napi_value returnVal = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, &args[0], &returnVal);
        if (removeOACB->callbackRef != nullptr) {
            napi_delete_reference(env, removeOACB->callbackRef);
        }
    }
}

napi_value ParseParaSetOAName(napi_env env, napi_callback_info cbInfo, SetOANameAsyncContext *setOANameCB)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == 0 && valueType == napi_number) {
            setOANameCB->id = GetIntProperty(env, argv[i]);
        } else if (i == 1 && valueType == napi_string) {
            setOANameCB->name = GetStringProperty(env, argv[i]);
        } else if (valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &setOANameCB->callbackRef);
            break;
        } else {
            ACCOUNT_LOGE("Type matching failed");
            return nullptr;
        }
    }
    return WrapVoidToJS(env);
}

void SetOANameExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    SetOANameAsyncContext *setOANameCB = reinterpret_cast<SetOANameAsyncContext *>(data);
    setOANameCB->errCode = OsAccountManager::SetOsAccountName(setOANameCB->id, setOANameCB->name);
    ACCOUNT_LOGI("errcode is %{public}d", setOANameCB->errCode);
    setOANameCB->status = (setOANameCB->errCode == 0) ? napi_ok : napi_generic_failure;
}

void SetOANameCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    SetOANameAsyncContext *setOANameCB = reinterpret_cast<SetOANameAsyncContext *>(data);
    napi_value setNameResult[RESULT_COUNT] = {0};
    setNameResult[PARAMZERO] = GetErrorCodeValue(env, setOANameCB->errCode);
    napi_get_undefined(env, &setNameResult[PARAMONE]);
    CBOrPromiseToSetOAName(env, setOANameCB, setNameResult[PARAMZERO], setNameResult[PARAMONE]);
    napi_delete_async_work(env, setOANameCB->work);
    delete setOANameCB;
    setOANameCB = nullptr;
}

void CBOrPromiseToSetOAName(napi_env env, const SetOANameAsyncContext *setOANameCB, napi_value err, napi_value data)
{
    ACCOUNT_LOGI("enter");
    napi_value args[RESULT_COUNT] = {err, data};
    if (setOANameCB->deferred) {
        ACCOUNT_LOGI("Promise");
        if (setOANameCB->status == napi_ok) {
            napi_resolve_deferred(env, setOANameCB->deferred, args[1]);
        } else {
            napi_reject_deferred(env, setOANameCB->deferred, args[0]);
        }
    } else {
        ACCOUNT_LOGI("Callback");
        napi_value callback = nullptr;
        napi_get_reference_value(env, setOANameCB->callbackRef, &callback);
        napi_value returnVal = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, &args[0], &returnVal);
        if (setOANameCB->callbackRef != nullptr) {
            napi_delete_reference(env, setOANameCB->callbackRef);
        }
    }
}

napi_value ParseParaSetOAConstraints(napi_env env, napi_callback_info cbInfo, SetOAConsAsyncContext *setOAConsCB)
{
    ACCOUNT_LOGI("enter");

    uint32_t length = 0;
    size_t strLen = 0;
    bool isArray = false;
    size_t argc = ARGS_SIZE_FOUR;
    napi_valuetype valueType = napi_undefined;
    napi_value argv[ARGS_SIZE_FOUR] = {0};
    NAPI_CALL(env, napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr));
    ACCOUNT_LOGI("argc = [%{public}zu]", argc);

    // argv[0] : localId
    NAPI_CALL(env, napi_typeof(env, argv[0], &valueType));
    if (valueType == napi_number) {
        setOAConsCB->id = GetIntProperty(env, argv[0]);
    } else {
        ACCOUNT_LOGI("Wrong argument type");
        return nullptr;
    }

    // argv[1] : Array<string>
    NAPI_CALL(env, napi_is_array(env, argv[1], &isArray));
    NAPI_ASSERT(env, isArray, "Wrong argument type for arg1. Array<string> expected.");
    if (isArray) {
        NAPI_CALL(env, napi_get_array_length(env, argv[1], &length));
        NAPI_ASSERT(env, length > 0, "The array is empty.");
        for (size_t i = 0; i < length; i++) {
            napi_value consStr = nullptr;
            napi_get_element(env, argv[1], i, &consStr);
            NAPI_CALL(env, napi_typeof(env, consStr, &valueType));
            NAPI_ASSERT(env, valueType == napi_string, "Wrong argument type. String expected.");
            char str[STR_MAX_SIZE] = {0};
            NAPI_CALL(env, napi_get_value_string_utf8(env, consStr, str, STR_MAX_SIZE - 1, &strLen));
            setOAConsCB->constraints.emplace_back(str);
        }
    }

    // argv[2] : enable
    NAPI_CALL(env, napi_typeof(env, argv[PARAMTWO], &valueType));
    if (valueType == napi_boolean) {
        NAPI_CALL(env, napi_get_value_bool(env, argv[PARAMTWO], &setOAConsCB->enable));
    } else {
        ACCOUNT_LOGI("Wrong argument type");
        return nullptr;
    }

    // argv[3] : callback
    if (argc >= ARGS_SIZE_FOUR) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAMTHREE], &valueType));
        NAPI_ASSERT(env, valueType == napi_function, "Wrong argument type. Function expected.");
        NAPI_CALL(env, napi_create_reference(env, argv[PARAMTHREE], 1, &setOAConsCB->callbackRef));
    }

    return WrapVoidToJS(env);
}

void SetOAConsExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    SetOAConsAsyncContext *setOAConsCB = reinterpret_cast<SetOAConsAsyncContext *>(data);
    setOAConsCB->errCode =
        OsAccountManager::SetOsAccountConstraints(setOAConsCB->id, setOAConsCB->constraints, setOAConsCB->enable);
    ACCOUNT_LOGI("errcode is %{public}d", setOAConsCB->errCode);
    setOAConsCB->status = (setOAConsCB->errCode == 0) ? napi_ok : napi_generic_failure;
}

void SetOAConsCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    SetOAConsAsyncContext *setOAConsCB = reinterpret_cast<SetOAConsAsyncContext *>(data);
    napi_value setConsResult[RESULT_COUNT] = {0};
    setConsResult[PARAMZERO] = GetErrorCodeValue(env, setOAConsCB->errCode);
    napi_get_undefined(env, &setConsResult[PARAMONE]);
    CBOrPromiseToSetOACons(env, setOAConsCB, setConsResult[PARAMZERO], setConsResult[PARAMONE]);
    napi_delete_async_work(env, setOAConsCB->work);
    delete setOAConsCB;
    setOAConsCB = nullptr;
}

void CBOrPromiseToSetOACons(napi_env env, const SetOAConsAsyncContext *setOAConsCB, napi_value err, napi_value data)
{
    ACCOUNT_LOGI("enter");
    napi_value args[RESULT_COUNT] = {err, data};
    if (setOAConsCB->deferred) {
        ACCOUNT_LOGI("Promise");
        if (setOAConsCB->status == napi_ok) {
            napi_resolve_deferred(env, setOAConsCB->deferred, args[1]);
        } else {
            napi_reject_deferred(env, setOAConsCB->deferred, args[0]);
        }
    } else {
        ACCOUNT_LOGI("Callback");
        napi_value callback = nullptr;
        napi_get_reference_value(env, setOAConsCB->callbackRef, &callback);
        napi_value returnVal = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, &args[0], &returnVal);
        if (setOAConsCB->callbackRef != nullptr) {
            napi_delete_reference(env, setOAConsCB->callbackRef);
        }
    }
}

napi_value ParseParaActiveOA(napi_env env, napi_callback_info cbInfo, ActivateOAAsyncContext *activeOACB)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == 0 && valueType == napi_number) {
            activeOACB->id = GetIntProperty(env, argv[i]);
        } else if (valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &activeOACB->callbackRef);
            break;
        } else {
            ACCOUNT_LOGE("Type matching failed");
            return nullptr;
        }
    }
    return WrapVoidToJS(env);
}

void ActivateOAExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    ActivateOAAsyncContext *activateOACB = reinterpret_cast<ActivateOAAsyncContext *>(data);
    activateOACB->errCode = OsAccountManager::ActivateOsAccount(activateOACB->id);
    ACCOUNT_LOGI("errcode is %{public}d", activateOACB->errCode);
    activateOACB->status = (activateOACB->errCode == 0) ? napi_ok : napi_generic_failure;
}

void ActivateOACallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    ActivateOAAsyncContext *activateOA = reinterpret_cast<ActivateOAAsyncContext *>(data);
    napi_value activateResult[RESULT_COUNT] = {0};
    activateResult[PARAMZERO] = GetErrorCodeValue(env, activateOA->errCode);
    napi_get_undefined(env, &activateResult[PARAMONE]);
    CBOrPromiseToActivateOA(env, activateOA, activateResult[PARAMZERO], activateResult[PARAMONE]);
    napi_delete_async_work(env, activateOA->work);
    delete activateOA;
    activateOA = nullptr;
}

void CBOrPromiseToActivateOA(napi_env env, const ActivateOAAsyncContext *activateOA, napi_value err, napi_value data)
{
    ACCOUNT_LOGI("enter");
    napi_value args[RESULT_COUNT] = {err, data};
    if (activateOA->deferred) {
        ACCOUNT_LOGI("Promise");
        if (activateOA->status == napi_ok) {
            napi_resolve_deferred(env, activateOA->deferred, args[1]);
        } else {
            napi_reject_deferred(env, activateOA->deferred, args[0]);
        }
    } else {
        ACCOUNT_LOGI("Callback");
        napi_value callback = nullptr;
        napi_get_reference_value(env, activateOA->callbackRef, &callback);
        napi_value returnVal = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, &args[0], &returnVal);
        if (activateOA->callbackRef != nullptr) {
            napi_delete_reference(env, activateOA->callbackRef);
        }
    }
}

napi_value ParseParaCreateOA(napi_env env, napi_callback_info cbInfo, CreateOAAsyncContext *createOACB)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == 0 && valueType == napi_string) {
            createOACB->name = GetStringProperty(env, argv[i]);
        } else if (i == 1 && valueType == napi_number) {
            createOACB->type = static_cast<OsAccountType>(GetIntProperty(env, argv[i]));
        } else if (i == PARAMTWO && valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &createOACB->callbackRef);
            break;
        } else {
            ACCOUNT_LOGE("Type matching failed");
            return nullptr;
        }
    }
    return WrapVoidToJS(env);
}

napi_value ParseParaCreateOAForDomain(napi_env env, napi_callback_info cbInfo,
    CreateOAForDomainAsyncContext *createOAForDomainCB)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    for (size_t i = PARAMZERO; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == PARAMZERO && valueType == napi_number) {
            createOAForDomainCB->type = static_cast<OsAccountType>(GetIntProperty(env, argv[i]));
        } else if (i == PARAMONE && valueType == napi_object) {
            napi_value result = nullptr;
            napi_get_named_property(env, argv[i], "domain", &result);
            createOAForDomainCB->domainInfo.domain_ = GetStringProperty(env, result);

            result = nullptr;
            napi_get_named_property(env, argv[i], "accountName", &result);
            createOAForDomainCB->domainInfo.accountName_ = GetStringProperty(env, result);
        } else if (i == PARAMTWO && valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &createOAForDomainCB->callbackRef);
            break;
        } else {
            ACCOUNT_LOGE("Type matching failed");
            return nullptr;
        }
    }
    return WrapVoidToJS(env);
}

void CreateOAExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    CreateOAAsyncContext *createOACB = reinterpret_cast<CreateOAAsyncContext *>(data);
    createOACB->errCode =
        OsAccountManager::CreateOsAccount(createOACB->name, createOACB->type, createOACB->osAccountInfos);
    ACCOUNT_LOGI("errocde is %{public}d", createOACB->errCode);
    createOACB->status = (createOACB->errCode == 0) ? napi_ok : napi_generic_failure;
}

void CreateOAForDomainExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    CreateOAForDomainAsyncContext *createOAForDomainCB = reinterpret_cast<CreateOAForDomainAsyncContext *>(data);
    createOAForDomainCB->errCode = OsAccountManager::CreateOsAccountForDomain(createOAForDomainCB->type,
        createOAForDomainCB->domainInfo, createOAForDomainCB->osAccountInfos);
    ACCOUNT_LOGI("errocde is %{public}d", createOAForDomainCB->errCode);
    createOAForDomainCB->status = (createOAForDomainCB->errCode == 0) ? napi_ok : napi_generic_failure;
}

void CreateOACallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    CreateOAAsyncContext *createOACB = reinterpret_cast<CreateOAAsyncContext *>(data);
    napi_value createResult[RESULT_COUNT] = {0};
    createResult[PARAMZERO] = GetErrorCodeValue(env, createOACB->errCode);
    napi_create_object(env, &createResult[PARAMONE]);
    GetOACBInfoToJs(env, createOACB->osAccountInfos, createResult[PARAMONE]);
    CBOrPromiseToCreateOA(env, createOACB, createResult[PARAMZERO], createResult[PARAMONE]);
    napi_delete_async_work(env, createOACB->work);
    delete createOACB;
    createOACB = nullptr;
}

void CreateOAForDomainCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    CreateOAForDomainAsyncContext *createOAForDomainCB = reinterpret_cast<CreateOAForDomainAsyncContext *>(data);
    napi_value createResult[RESULT_COUNT] = {0};
    createResult[PARAMZERO] = GetErrorCodeValue(env, createOAForDomainCB->errCode);
    napi_create_object(env, &createResult[PARAMONE]);
    GetOACBInfoToJs(env, createOAForDomainCB->osAccountInfos, createResult[PARAMONE]);
    CBOrPromiseToCreateOAForDomain(env, createOAForDomainCB, createResult[PARAMZERO], createResult[PARAMONE]);
    napi_delete_async_work(env, createOAForDomainCB->work);
    delete createOAForDomainCB;
    createOAForDomainCB = nullptr;
}

void CBOrPromiseToCreateOA(napi_env env, const CreateOAAsyncContext *createOACB, napi_value err, napi_value data)
{
    ACCOUNT_LOGI("enter");
    napi_value args[RESULT_COUNT] = {err, data};
    if (createOACB->deferred) {
        ACCOUNT_LOGI("Promise");
        if (createOACB->status == napi_ok) {
            napi_resolve_deferred(env, createOACB->deferred, args[1]);
        } else {
            napi_reject_deferred(env, createOACB->deferred, args[0]);
        }
    } else {
        ACCOUNT_LOGI("Callback");
        napi_value callback = nullptr;
        napi_get_reference_value(env, createOACB->callbackRef, &callback);
        napi_value returnVal = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, &args[0], &returnVal);
        if (createOACB->callbackRef != nullptr) {
            napi_delete_reference(env, createOACB->callbackRef);
        }
    }
}

void CBOrPromiseToCreateOAForDomain(napi_env env, const CreateOAForDomainAsyncContext *createOAForDomainCB,
    napi_value err, napi_value data)
{
    ACCOUNT_LOGI("enter");
    napi_value args[RESULT_COUNT] = {err, data};
    if (createOAForDomainCB->deferred) {
        ACCOUNT_LOGI("Promise");
        if (createOAForDomainCB->status == napi_ok) {
            napi_resolve_deferred(env, createOAForDomainCB->deferred, args[1]);
        } else {
            napi_reject_deferred(env, createOAForDomainCB->deferred, args[0]);
        }
    } else {
        ACCOUNT_LOGI("Callback");
        napi_value callback = nullptr;
        napi_get_reference_value(env, createOAForDomainCB->callbackRef, &callback);
        napi_value returnVal = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, &args[0], &returnVal);
        if (createOAForDomainCB->callbackRef != nullptr) {
            napi_delete_reference(env, createOAForDomainCB->callbackRef);
        }
    }
}

void ParseParaGetOACount(napi_env env, napi_callback_info cbInfo, GetOACountAsyncContext *getOACount)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[0], &valueType);
    if (valueType == napi_function) {
        napi_create_reference(env, argv[0], 1, &getOACount->callbackRef);
    } else {
        ACCOUNT_LOGE("Type matching failed");
    }
}

void GetOACountExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    GetOACountAsyncContext *getOACount = reinterpret_cast<GetOACountAsyncContext *>(data);
    getOACount->errCode = OsAccountManager::GetCreatedOsAccountsCount(getOACount->osAccountsCount);
    ACCOUNT_LOGI("errocde is %{public}d", getOACount->errCode);
    getOACount->status = (getOACount->errCode == 0) ? napi_ok : napi_generic_failure;
}

void GetOACountCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    GetOACountAsyncContext *getOACount = reinterpret_cast<GetOACountAsyncContext *>(data);
    napi_value getResult[RESULT_COUNT] = {0};
    getResult[PARAMZERO] = GetErrorCodeValue(env, getOACount->errCode);
    napi_create_uint32(env, getOACount->osAccountsCount, &getResult[PARAMONE]);
    CBOrPromiseToGetOACount(env, getOACount, getResult[PARAMZERO], getResult[PARAMONE]);
    napi_delete_async_work(env, getOACount->work);
    delete getOACount;
    getOACount = nullptr;
}

void CBOrPromiseToGetOACount(napi_env env, const GetOACountAsyncContext *getOACount, napi_value err, napi_value data)
{
    ACCOUNT_LOGI("enter");
    napi_value args[RESULT_COUNT] = {err, data};
    if (getOACount->deferred) {
        ACCOUNT_LOGI("Promise");
        if (getOACount->status == napi_ok) {
            napi_resolve_deferred(env, getOACount->deferred, args[1]);
        } else {
            napi_reject_deferred(env, getOACount->deferred, args[0]);
        }
    } else {
        ACCOUNT_LOGI("Callback");
        napi_value callback = nullptr;
        napi_get_reference_value(env, getOACount->callbackRef, &callback);
        napi_value returnVal = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, &args[0], &returnVal);
        if (getOACount->callbackRef != nullptr) {
            napi_delete_reference(env, getOACount->callbackRef);
        }
    }
}

void ParseParaDbDeviceId(napi_env env, napi_callback_info cbInfo, DbDeviceIdAsyncContext *dbDeviceId)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[0], &valueType);
    if (valueType == napi_function) {
        napi_create_reference(env, argv[0], 1, &dbDeviceId->callbackRef);
    } else {
        ACCOUNT_LOGE("Type matching failed");
    }
}

void DbDeviceIdExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    DbDeviceIdAsyncContext *dbDeviceId = reinterpret_cast<DbDeviceIdAsyncContext *>(data);
    dbDeviceId->errCode = OsAccountManager::GetDistributedVirtualDeviceId(dbDeviceId->deviceId);
    ACCOUNT_LOGI("errocde is %{public}d", dbDeviceId->errCode);
    dbDeviceId->status = (dbDeviceId->errCode == 0) ? napi_ok : napi_generic_failure;
}

void DbDeviceIdCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    DbDeviceIdAsyncContext *dbDeviceId = reinterpret_cast<DbDeviceIdAsyncContext *>(data);
    napi_value dbIdResult[RESULT_COUNT] = {0};
    dbIdResult[PARAMZERO] = GetErrorCodeValue(env, dbDeviceId->errCode);
    napi_create_string_utf8(env, dbDeviceId->deviceId.c_str(), NAPI_AUTO_LENGTH, &dbIdResult[PARAMONE]);
    CBOrPromiseToDbDeviceId(env, dbDeviceId, dbIdResult[PARAMZERO], dbIdResult[PARAMONE]);
    napi_delete_async_work(env, dbDeviceId->work);
    delete dbDeviceId;
    dbDeviceId = nullptr;
}

void CBOrPromiseToDbDeviceId(napi_env env, const DbDeviceIdAsyncContext *dbDeviceId, napi_value err, napi_value data)
{
    ACCOUNT_LOGI("enter");
    napi_value args[RESULT_COUNT] = {err, data};
    if (dbDeviceId->deferred) {
        ACCOUNT_LOGI("Promise");
        if (dbDeviceId->status == napi_ok) {
            napi_resolve_deferred(env, dbDeviceId->deferred, args[1]);
        } else {
            napi_reject_deferred(env, dbDeviceId->deferred, args[0]);
        }
    } else {
        ACCOUNT_LOGI("Callback");
        napi_value callback = nullptr;
        napi_get_reference_value(env, dbDeviceId->callbackRef, &callback);
        napi_value returnVal = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, &args[0], &returnVal);
        if (dbDeviceId->callbackRef != nullptr) {
            napi_delete_reference(env, dbDeviceId->callbackRef);
        }
    }
}

napi_value ParseParaGetAllCons(napi_env env, napi_callback_info cbInfo, GetAllConsAsyncContext *getAllConsCB)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == 0 && valueType == napi_number) {
            getAllConsCB->id = GetIntProperty(env, argv[i]);
        } else if (valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &getAllConsCB->callbackRef);
            break;
        } else {
            ACCOUNT_LOGE("Type matching failed");
            return nullptr;
        }
    }
    return WrapVoidToJS(env);
}

void GetAllConsExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    GetAllConsAsyncContext *getAllConsCB = reinterpret_cast<GetAllConsAsyncContext *>(data);
    getAllConsCB->errCode = OsAccountManager::GetOsAccountAllConstraints(getAllConsCB->id, getAllConsCB->constraints);
    ACCOUNT_LOGI("errocde is %{public}d", getAllConsCB->errCode);
    getAllConsCB->status = (getAllConsCB->errCode == 0) ? napi_ok : napi_generic_failure;
}

void GetAllConsCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    GetAllConsAsyncContext *getAllConsCB = reinterpret_cast<GetAllConsAsyncContext *>(data);
    napi_value getResult[RESULT_COUNT] = {0};
    getResult[PARAMZERO] = GetErrorCodeValue(env, getAllConsCB->errCode);
    napi_create_array(env, &getResult[PARAMONE]);
    GetAllAccountCons(env, getAllConsCB->constraints, getResult[PARAMONE]);
    CBOrPromiseToGetAllCons(env, getAllConsCB, getResult[PARAMZERO], getResult[PARAMONE]);
    napi_delete_async_work(env, getAllConsCB->work);
    delete getAllConsCB;
    getAllConsCB = nullptr;
}

void GetAllAccountCons(napi_env env, const std::vector<std::string> &info, napi_value result)
{
    ACCOUNT_LOGI("enter");

    uint32_t index = 0;

    for (auto item : info) {
        napi_value consStr = nullptr;
        napi_create_string_utf8(env, item.c_str(), NAPI_AUTO_LENGTH, &consStr);
        napi_set_element(env, result, index, consStr);
        index++;
    }
}

void GetActiveIds(napi_env env, const std::vector<int> &ids, napi_value result)
{
    ACCOUNT_LOGI("enter");

    uint32_t index = 0;

    for (auto id : ids) {
        napi_value tempID = nullptr;
        napi_create_int32(env, id, &tempID);
        napi_set_element(env, result, index, tempID);
        index++;
    }
}

void CBOrPromiseToGetAllCons(napi_env env, const GetAllConsAsyncContext *getAllCons, napi_value err, napi_value data)
{
    ACCOUNT_LOGI("enter");
    napi_value args[RESULT_COUNT] = {err, data};
    if (getAllCons->deferred) {
        ACCOUNT_LOGI("Promise");
        if (getAllCons->status == napi_ok) {
            napi_resolve_deferred(env, getAllCons->deferred, args[1]);
        } else {
            napi_reject_deferred(env, getAllCons->deferred, args[0]);
        }
    } else {
        ACCOUNT_LOGI("Callback");
        napi_value callback = nullptr;
        napi_get_reference_value(env, getAllCons->callbackRef, &callback);
        napi_value returnVal = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, &args[0], &returnVal);
        if (getAllCons->callbackRef != nullptr) {
            napi_delete_reference(env, getAllCons->callbackRef);
        }
    }
}

void ParseParaProcessId(napi_env env, napi_callback_info cbInfo, GetIdAsyncContext *getIdCB)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[0], &valueType);
    if (valueType == napi_function) {
        napi_create_reference(env, argv[0], 1, &getIdCB->callbackRef);
    } else {
        ACCOUNT_LOGE("Type matching failed");
    }
}

void GetProcessIdExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    GetIdAsyncContext *getIdCB = reinterpret_cast<GetIdAsyncContext *>(data);
    getIdCB->errCode = OsAccountManager::GetOsAccountLocalIdFromProcess(getIdCB->id);
    ACCOUNT_LOGI("errocde is %{public}d", getIdCB->errCode);
    getIdCB->status = (getIdCB->errCode == 0) ? napi_ok : napi_generic_failure;
}

void GetProcessIdCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    GetIdAsyncContext *getIdCB = reinterpret_cast<GetIdAsyncContext *>(data);
    napi_value getResult[RESULT_COUNT] = {0};
    getResult[PARAMZERO] = GetErrorCodeValue(env, getIdCB->errCode);
    napi_create_int32(env, getIdCB->id, &getResult[PARAMONE]);
    CBOrPromiseToGetProcessId(env, getIdCB, getResult[PARAMZERO], getResult[PARAMONE]);
    napi_delete_async_work(env, getIdCB->work);
    delete getIdCB;
    getIdCB = nullptr;
}

void CBOrPromiseToGetProcessId(napi_env env, const GetIdAsyncContext *getIdCB, napi_value err, napi_value data)
{
    ACCOUNT_LOGI("enter");
    napi_value args[RESULT_COUNT] = {err, data};
    if (getIdCB->deferred) {
        ACCOUNT_LOGI("Promise");
        if (getIdCB->status == napi_ok) {
            napi_resolve_deferred(env, getIdCB->deferred, args[1]);
        } else {
            napi_reject_deferred(env, getIdCB->deferred, args[0]);
        }
    } else {
        ACCOUNT_LOGI("Callback");
        napi_value callback = nullptr;
        napi_get_reference_value(env, getIdCB->callbackRef, &callback);
        napi_value returnVal = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, &args[0], &returnVal);
        if (getIdCB->callbackRef != nullptr) {
            napi_delete_reference(env, getIdCB->callbackRef);
        }
    }
}

void ParseQueryAllCreateOA(napi_env env, napi_callback_info cbInfo, QueryCreateOAAsyncContext *queryAllOA)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[0], &valueType);
    if (valueType == napi_function) {
        napi_create_reference(env, argv[0], 1, &queryAllOA->callbackRef);
    } else {
        ACCOUNT_LOGE("Type matching failed");
    }
}

napi_value ParseQueryOAConstraintSrcTypes(napi_env env, napi_callback_info cbInfo,
    QueryOAConstraintSrcTypeContext *queryConstraintSource)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == 0 && valueType == napi_number) {
            queryConstraintSource->id = GetIntProperty(env, argv[i]);
        } else if (i == 1 && valueType == napi_string) {
            queryConstraintSource->constraint = GetStringProperty(env, argv[i]);
        } else if (valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &queryConstraintSource->callbackRef);
            break;
        } else {
            ACCOUNT_LOGE("Type matching failed");
            return nullptr;
        }
    }
    return WrapVoidToJS(env);
}

void QueryOAContSrcTypeExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    QueryOAConstraintSrcTypeContext *queryConstraintSource = reinterpret_cast<QueryOAConstraintSrcTypeContext *>(data);
    queryConstraintSource->errCode = OsAccountManager::QueryOsAccountConstraintSourceTypes(queryConstraintSource->id,
        queryConstraintSource->constraint, queryConstraintSource->constraintSourceTypeInfos);
    ACCOUNT_LOGI("errocde is %{public}d", queryConstraintSource->errCode);
    queryConstraintSource->status = (queryConstraintSource->errCode == 0) ? napi_ok : napi_generic_failure;
}

void QueryOAContSrcTypeCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    QueryOAConstraintSrcTypeContext *queryConstraintSource = reinterpret_cast<QueryOAConstraintSrcTypeContext *>(data);
    napi_value queryResult[RESULT_COUNT] = {0};
    queryResult[PARAMZERO] = GetErrorCodeValue(env, queryConstraintSource->errCode);
    napi_create_array(env, &queryResult[PARAMONE]);
    QueryOAContSrcTypeForResult(env, queryConstraintSource->constraintSourceTypeInfos, queryResult[PARAMONE]);
    CBOrPromiseToQueryOAContSrcType(env, queryConstraintSource, queryResult[PARAMZERO], queryResult[PARAMONE]);
    napi_delete_async_work(env, queryConstraintSource->work);
    delete queryConstraintSource;
    queryConstraintSource = nullptr;
}

void QueryOAContSrcTypeForResult(napi_env env, const std::vector<ConstraintSourceTypeInfo> &infos, napi_value result)
{
    ACCOUNT_LOGD("enter");

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

void CBOrPromiseToQueryOAContSrcType(napi_env env,
    const QueryOAConstraintSrcTypeContext *queryConstraintSource, napi_value err, napi_value data)
{
    ACCOUNT_LOGI("enter");
    napi_value args[RESULT_COUNT] = {err, data};
    if (queryConstraintSource->deferred) {
        ACCOUNT_LOGI("Promise");
        if (queryConstraintSource->status == napi_ok) {
            napi_resolve_deferred(env, queryConstraintSource->deferred, args[1]);
        } else {
            napi_reject_deferred(env, queryConstraintSource->deferred, args[0]);
        }
    } else {
        ACCOUNT_LOGI("Callback");
        napi_value callback = nullptr;
        napi_get_reference_value(env, queryConstraintSource->callbackRef, &callback);
        napi_value returnVal = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, &args[0], &returnVal);
        if (queryConstraintSource->callbackRef != nullptr) {
            napi_delete_reference(env, queryConstraintSource->callbackRef);
        }
    }
}

void ParseQueryActiveIds(napi_env env, napi_callback_info cbInfo, QueryActiveIdsAsyncContext *queryActiveIds)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[0], &valueType);
    if (valueType == napi_function) {
        napi_create_reference(env, argv[0], 1, &queryActiveIds->callbackRef);
    }
}

void QueryCreateOAExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    QueryCreateOAAsyncContext *queryAllOA = reinterpret_cast<QueryCreateOAAsyncContext *>(data);
    queryAllOA->errCode = OsAccountManager::QueryAllCreatedOsAccounts(queryAllOA->osAccountInfos);
    ACCOUNT_LOGI("errocde is %{public}d", queryAllOA->errCode);
    queryAllOA->status = (queryAllOA->errCode == 0) ? napi_ok : napi_generic_failure;
}

void QueryActiveIdsExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    QueryActiveIdsAsyncContext *queryActiveIds = reinterpret_cast<QueryActiveIdsAsyncContext *>(data);
    queryActiveIds->errCode = OsAccountManager::QueryActiveOsAccountIds(queryActiveIds->osAccountIds);
    ACCOUNT_LOGI("errocde is %{public}d", queryActiveIds->errCode);
    queryActiveIds->status = (queryActiveIds->errCode == 0) ? napi_ok : napi_generic_failure;
}

void QueryCreateOACallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    QueryCreateOAAsyncContext *queryAllOA = reinterpret_cast<QueryCreateOAAsyncContext *>(data);
    napi_value queryResult[RESULT_COUNT] = {0};
    queryResult[PARAMZERO] = GetErrorCodeValue(env, queryAllOA->errCode);
    napi_create_array(env, &queryResult[PARAMONE]);
    QueryOAInfoForResult(env, queryAllOA->osAccountInfos, queryResult[PARAMONE]);
    CBOrPromiseToQueryOA(env, queryAllOA, queryResult[PARAMZERO], queryResult[PARAMONE]);
    napi_delete_async_work(env, queryAllOA->work);
    delete queryAllOA;
    queryAllOA = nullptr;
}

void QueryActiveIdsCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    QueryActiveIdsAsyncContext *queryActiveIds = reinterpret_cast<QueryActiveIdsAsyncContext *>(data);
    napi_value queryResult[RESULT_COUNT] = {0};
    queryResult[PARAMZERO] = GetErrorCodeValue(env, queryActiveIds->errCode);
    napi_create_array(env, &queryResult[PARAMONE]);
    GetActiveIds(env, queryActiveIds->osAccountIds, queryResult[PARAMONE]);
    CBOrPromiseToQueryActiveIds(env, queryActiveIds, queryResult[PARAMZERO], queryResult[PARAMONE]);
    napi_delete_async_work(env, queryActiveIds->work);
    delete queryActiveIds;
    queryActiveIds = nullptr;
}

void QueryOAInfoForResult(napi_env env, const std::vector<OsAccountInfo> &info, napi_value result)
{
    ACCOUNT_LOGI("enter");

    uint32_t index = 0;

    for (auto item : info) {
        napi_value objOAInfo = nullptr;
        napi_create_object(env, &objOAInfo);
        GetOACBInfoToJs(env, item, objOAInfo);
        napi_set_element(env, result, index, objOAInfo);
        index++;
    }
}

void CBOrPromiseToQueryOA(napi_env env, const QueryCreateOAAsyncContext *queryOA, napi_value err, napi_value data)
{
    ACCOUNT_LOGI("enter");
    napi_value args[RESULT_COUNT] = {err, data};
    if (queryOA->deferred) {
        ACCOUNT_LOGI("Promise");
        if (queryOA->status == napi_ok) {
            napi_resolve_deferred(env, queryOA->deferred, args[1]);
        } else {
            napi_reject_deferred(env, queryOA->deferred, args[0]);
        }
    } else {
        ACCOUNT_LOGI("Callback");
        napi_value callback = nullptr;
        napi_get_reference_value(env, queryOA->callbackRef, &callback);
        napi_value returnVal = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, &args[0], &returnVal);
        if (queryOA->callbackRef != nullptr) {
            napi_delete_reference(env, queryOA->callbackRef);
        }
    }
}

void CBOrPromiseToQueryActiveIds(napi_env env, const QueryActiveIdsAsyncContext *queryActiveIds,
    napi_value err, napi_value data)
{
    ACCOUNT_LOGI("enter");
    napi_value args[RESULT_COUNT] = {err, data};
    if (queryActiveIds->deferred) {
        ACCOUNT_LOGI("Promise");
        if (queryActiveIds->status == napi_ok) {
            napi_resolve_deferred(env, queryActiveIds->deferred, args[1]);
        } else {
            napi_reject_deferred(env, queryActiveIds->deferred, args[0]);
        }
    } else {
        ACCOUNT_LOGI("Callback");
        napi_value callback = nullptr;
        napi_get_reference_value(env, queryActiveIds->callbackRef, &callback);
        napi_value returnVal = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, &args[0], &returnVal);
        if (queryActiveIds->callbackRef != nullptr) {
            napi_delete_reference(env, queryActiveIds->callbackRef);
        }
    }
}

napi_value ParseParaGetPhote(napi_env env, napi_callback_info cbInfo, GetOAPhotoAsyncContext *getPhoto)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == 0 && valueType == napi_number) {
            getPhoto->id = GetIntProperty(env, argv[i]);
        } else if (valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &getPhoto->callbackRef);
            break;
        } else {
            ACCOUNT_LOGE("Type matching failed");
            return nullptr;
        }
    }
    return WrapVoidToJS(env);
}

void GetOAPhoteExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    GetOAPhotoAsyncContext *getPhoto = reinterpret_cast<GetOAPhotoAsyncContext *>(data);
    getPhoto->errCode = OsAccountManager::GetOsAccountProfilePhoto(getPhoto->id, getPhoto->photo);
    ACCOUNT_LOGI("errocde is %{public}d", getPhoto->errCode);
    getPhoto->status = (getPhoto->errCode == 0) ? napi_ok : napi_generic_failure;
}

void GetOAPhoteCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    GetOAPhotoAsyncContext *getPhoto = reinterpret_cast<GetOAPhotoAsyncContext *>(data);
    napi_value getResult[RESULT_COUNT] = {0};
    getResult[PARAMZERO] = GetErrorCodeValue(env, getPhoto->errCode);
    napi_create_string_utf8(env, getPhoto->photo.c_str(), NAPI_AUTO_LENGTH, &getResult[PARAMONE]);
    CBOrPromiseToGetPhoto(env, getPhoto, getResult[PARAMZERO], getResult[PARAMONE]);
    napi_delete_async_work(env, getPhoto->work);
    delete getPhoto;
    getPhoto = nullptr;
}

void CBOrPromiseToGetPhoto(napi_env env, const GetOAPhotoAsyncContext *getPhoto, napi_value err, napi_value data)
{
    ACCOUNT_LOGI("enter");
    napi_value args[RESULT_COUNT] = {err, data};
    if (getPhoto->deferred) {
        ACCOUNT_LOGI("Promise");
        if (getPhoto->status == napi_ok) {
            napi_resolve_deferred(env, getPhoto->deferred, args[1]);
        } else {
            napi_reject_deferred(env, getPhoto->deferred, args[0]);
        }
    } else {
        ACCOUNT_LOGI("Callback");
        napi_value callback = nullptr;
        napi_get_reference_value(env, getPhoto->callbackRef, &callback);
        napi_value returnVal = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, &args[0], &returnVal);
        if (getPhoto->callbackRef != nullptr) {
            napi_delete_reference(env, getPhoto->callbackRef);
        }
    }
}

void ParseParaCurrentOA(napi_env env, napi_callback_info cbInfo, CurrentOAAsyncContext *currentOA)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[0], &valueType);
    if (valueType == napi_function) {
        napi_create_reference(env, argv[0], 1, &currentOA->callbackRef);
    } else {
        ACCOUNT_LOGE("Type matching failed");
    }
}

void QueryCurrentOAExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    CurrentOAAsyncContext *currentOA = reinterpret_cast<CurrentOAAsyncContext *>(data);
    currentOA->errCode = OsAccountManager::QueryCurrentOsAccount(currentOA->osAccountInfos);
    ACCOUNT_LOGI("errocde is %{public}d", currentOA->errCode);
    currentOA->status = (currentOA->errCode == 0) ? napi_ok : napi_generic_failure;
}

void QueryCurrentOACallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    CurrentOAAsyncContext *currentOA = reinterpret_cast<CurrentOAAsyncContext *>(data);
    napi_value queryResult[RESULT_COUNT] = {0};
    queryResult[PARAMZERO] = GetErrorCodeValue(env, currentOA->errCode);
    napi_create_object(env, &queryResult[PARAMONE]);
    GetOACBInfoToJs(env, currentOA->osAccountInfos, queryResult[PARAMONE]);
    CBOrPromiseQueryCurrentOA(env, currentOA, queryResult[PARAMZERO], queryResult[PARAMONE]);
    napi_delete_async_work(env, currentOA->work);
    delete currentOA;
    currentOA = nullptr;
}

void CBOrPromiseQueryCurrentOA(napi_env env, const CurrentOAAsyncContext *currentOA, napi_value err, napi_value data)
{
    ACCOUNT_LOGI("enter");
    napi_value args[RESULT_COUNT] = {err, data};
    if (currentOA->deferred) {
        ACCOUNT_LOGI("Promise");
        if (currentOA->status == napi_ok) {
            napi_resolve_deferred(env, currentOA->deferred, args[1]);
        } else {
            napi_reject_deferred(env, currentOA->deferred, args[0]);
        }
    } else {
        ACCOUNT_LOGI("Callback");
        napi_value callback = nullptr;
        napi_get_reference_value(env, currentOA->callbackRef, &callback);
        napi_value returnVal = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, &args[0], &returnVal);
        if (currentOA->callbackRef != nullptr) {
            napi_delete_reference(env, currentOA->callbackRef);
        }
    }
}

napi_value ParseParaGetIdByUid(napi_env env, napi_callback_info cbInfo, GetIdByUidAsyncContext *idByUid)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == 0 && valueType == napi_number) {
            idByUid->uid = GetIntProperty(env, argv[i]);
        } else if (valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &idByUid->callbackRef);
            break;
        } else {
            ACCOUNT_LOGE("Type matching failed");
            return nullptr;
        }
    }
    return WrapVoidToJS(env);
}

napi_value ParseParaGetIdByDomain(napi_env env, napi_callback_info cbInfo, GetIdByDomainAsyncContext *idByDomain)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == PARAMZERO && valueType == napi_object) {
            napi_value result = nullptr;
            napi_get_named_property(env, argv[i], "domain", &result);
            idByDomain->domainInfo.domain_ = GetStringProperty(env, result);

            result = nullptr;
            napi_get_named_property(env, argv[i], "accountName", &result);
            idByDomain->domainInfo.accountName_ = GetStringProperty(env, result);
        } else if (i == PARAMONE && valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &idByDomain->callbackRef);
            break;
        } else {
            ACCOUNT_LOGE("Type matching failed");
            return nullptr;
        }
    }
    return WrapVoidToJS(env);
}

void GetIdByUidExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    GetIdByUidAsyncContext *idByUid = reinterpret_cast<GetIdByUidAsyncContext *>(data);
    idByUid->errCode = OsAccountManager::GetOsAccountLocalIdFromUid(idByUid->uid, idByUid->id);
    ACCOUNT_LOGI("errocde is %{public}d", idByUid->errCode);
    idByUid->status = (idByUid->errCode == 0) ? napi_ok : napi_generic_failure;
}

void GetBundleIdByUidExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    GetIdByUidAsyncContext *bundleIdByUid = reinterpret_cast<GetIdByUidAsyncContext *>(data);
    bundleIdByUid->errCode = OsAccountManager::GetBundleIdFromUid(bundleIdByUid->uid, bundleIdByUid->id);
    ACCOUNT_LOGI("errocde is %{public}d", bundleIdByUid->errCode);
    bundleIdByUid->status = (bundleIdByUid->errCode == 0) ? napi_ok : napi_generic_failure;
}

void GetIdByDomainExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    GetIdByDomainAsyncContext *idByDomain = reinterpret_cast<GetIdByDomainAsyncContext *>(data);
    idByDomain->errCode = OsAccountManager::GetOsAccountLocalIdFromDomain(
        idByDomain->domainInfo, idByDomain->id);
    ACCOUNT_LOGI("errocde is %{public}d", idByDomain->errCode);
    idByDomain->status = (idByDomain->errCode == 0) ? napi_ok : napi_generic_failure;
}

void GetIdByUidCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    GetIdByUidAsyncContext *idByUid = reinterpret_cast<GetIdByUidAsyncContext *>(data);
    napi_value uidResult[RESULT_COUNT] = {0};
    uidResult[PARAMZERO] = GetErrorCodeValue(env, idByUid->errCode);
    napi_create_int32(env, idByUid->id, &uidResult[PARAMONE]);
    CBOrPromiseGetIdByUid(env, idByUid, uidResult[PARAMZERO], uidResult[PARAMONE]);
    napi_delete_async_work(env, idByUid->work);
    delete idByUid;
    idByUid = nullptr;
}

void GetBundleIdByUidCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    GetIdByUidAsyncContext *bundleIdByUid = reinterpret_cast<GetIdByUidAsyncContext *>(data);
    napi_value bundleIdResult[RESULT_COUNT] = {0};
    bundleIdResult[PARAMZERO] = GetErrorCodeValue(env, bundleIdByUid->errCode);
    napi_create_int32(env, bundleIdByUid->id, &bundleIdResult[PARAMONE]);
    CBOrPromiseGetBundleIdByUid(env, bundleIdByUid, bundleIdResult[PARAMZERO], bundleIdResult[PARAMONE]);
    napi_delete_async_work(env, bundleIdByUid->work);
    delete bundleIdByUid;
    bundleIdByUid = nullptr;
}

void GetIdByDomainCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    GetIdByDomainAsyncContext *idByDomain = reinterpret_cast<GetIdByDomainAsyncContext *>(data);
    napi_value uidResult[RESULT_COUNT] = {0};
    uidResult[PARAMZERO] = GetErrorCodeValue(env, idByDomain->errCode);
    napi_create_int32(env, idByDomain->id, &uidResult[PARAMONE]);
    CBOrPromiseGetIdByDomain(env, idByDomain, uidResult[PARAMZERO], uidResult[PARAMONE]);
    napi_delete_async_work(env, idByDomain->work);
    delete idByDomain;
    idByDomain = nullptr;
}

void CBOrPromiseGetIdByUid(napi_env env, const GetIdByUidAsyncContext *idByUid, napi_value err, napi_value data)
{
    ACCOUNT_LOGI("enter");
    napi_value args[RESULT_COUNT] = {err, data};
    if (idByUid->deferred) {
        ACCOUNT_LOGI("Promise");
        if (idByUid->status == napi_ok) {
            napi_resolve_deferred(env, idByUid->deferred, args[1]);
        } else {
            napi_reject_deferred(env, idByUid->deferred, args[0]);
        }
    } else {
        ACCOUNT_LOGI("Callback");
        napi_value callback = nullptr;
        napi_get_reference_value(env, idByUid->callbackRef, &callback);
        napi_value returnVal = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, &args[0], &returnVal);
        if (idByUid->callbackRef != nullptr) {
            napi_delete_reference(env, idByUid->callbackRef);
        }
    }
}

void CBOrPromiseGetBundleIdByUid(napi_env env, const GetIdByUidAsyncContext *bundleIdByUid,
    napi_value err, napi_value data)
{
    ACCOUNT_LOGI("enter");
    napi_value args[RESULT_COUNT] = {err, data};
    if (bundleIdByUid->deferred) {
        ACCOUNT_LOGI("Promise");
        if (bundleIdByUid->status == napi_ok) {
            napi_resolve_deferred(env, bundleIdByUid->deferred, args[1]);
        } else {
            napi_reject_deferred(env, bundleIdByUid->deferred, args[0]);
        }
    } else {
        ACCOUNT_LOGI("Callback");
        napi_value callback = nullptr;
        napi_get_reference_value(env, bundleIdByUid->callbackRef, &callback);
        napi_value returnVal = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, &args[0], &returnVal);
        if (bundleIdByUid->callbackRef != nullptr) {
            napi_delete_reference(env, bundleIdByUid->callbackRef);
        }
    }
}

void CBOrPromiseGetIdByDomain(napi_env env, const GetIdByDomainAsyncContext *idByDomain,
    napi_value err, napi_value data)
{
    ACCOUNT_LOGI("enter");
    napi_value args[RESULT_COUNT] = {err, data};
    if (idByDomain->deferred) {
        ACCOUNT_LOGI("Promise");
        if (idByDomain->status == napi_ok) {
            napi_resolve_deferred(env, idByDomain->deferred, args[1]);
        } else {
            napi_reject_deferred(env, idByDomain->deferred, args[0]);
        }
    } else {
        ACCOUNT_LOGI("Callback");
        napi_value callback = nullptr;
        napi_get_reference_value(env, idByDomain->callbackRef, &callback);
        napi_value returnVal = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, &args[0], &returnVal);
        if (idByDomain->callbackRef != nullptr) {
            napi_delete_reference(env, idByDomain->callbackRef);
        }
    }
}

napi_value ParseParaSetPhoto(napi_env env, napi_callback_info cbInfo, SetOAPhotoAsyncContext *setPhoto)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == 0 && valueType == napi_number) {
            setPhoto->id = GetIntProperty(env, argv[i]);
        } else if (i == 1 && valueType == napi_string) {
            setPhoto->photo = GetStringProperty(env, argv[i]);
        } else if (valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &setPhoto->callbackRef);
            break;
        } else {
            ACCOUNT_LOGE("Type matching failed");
            return nullptr;
        }
    }
    return WrapVoidToJS(env);
}

void SetPhotoExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    SetOAPhotoAsyncContext *setPhoto = reinterpret_cast<SetOAPhotoAsyncContext *>(data);
    setPhoto->errCode = OsAccountManager::SetOsAccountProfilePhoto(setPhoto->id, setPhoto->photo);
    ACCOUNT_LOGI("errocde is %{public}d", setPhoto->errCode);
    setPhoto->status = (setPhoto->errCode == 0) ? napi_ok : napi_generic_failure;
}

void SetPhotoCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    SetOAPhotoAsyncContext *setPhoto = reinterpret_cast<SetOAPhotoAsyncContext *>(data);
    napi_value setResult[RESULT_COUNT] = {0};
    setResult[PARAMZERO] = GetErrorCodeValue(env, setPhoto->errCode);
    napi_get_undefined(env, &setResult[PARAMONE]);
    CBOrPromiseSetPhoto(env, setPhoto, setResult[PARAMZERO], setResult[PARAMONE]);
    napi_delete_async_work(env, setPhoto->work);
    delete setPhoto;
    setPhoto = nullptr;
}

void CBOrPromiseSetPhoto(napi_env env, const SetOAPhotoAsyncContext *setPhoto, napi_value err, napi_value data)
{
    ACCOUNT_LOGI("enter");
    napi_value args[RESULT_COUNT] = {err, data};
    if (setPhoto->deferred) {
        ACCOUNT_LOGI("Promise");
        if (setPhoto->status == napi_ok) {
            napi_resolve_deferred(env, setPhoto->deferred, args[1]);
        } else {
            napi_reject_deferred(env, setPhoto->deferred, args[0]);
        }
    } else {
        ACCOUNT_LOGI("Callback");
        napi_value callback = nullptr;
        napi_get_reference_value(env, setPhoto->callbackRef, &callback);
        napi_value returnVal = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, &args[0], &returnVal);
        if (setPhoto->callbackRef != nullptr) {
            napi_delete_reference(env, setPhoto->callbackRef);
        }
    }
}

void ParseParaQueryMaxNum(napi_env env, napi_callback_info cbInfo, QueryMaxNumAsyncContext *maxNum)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[0], &valueType);
    if (valueType == napi_function) {
        napi_create_reference(env, argv[0], 1, &maxNum->callbackRef);
    } else {
        ACCOUNT_LOGE("Type matching failed");
    }
}

void QueryMaxNumExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    QueryMaxNumAsyncContext *maxNum = reinterpret_cast<QueryMaxNumAsyncContext *>(data);
    maxNum->errCode = OsAccountManager::QueryMaxOsAccountNumber(maxNum->maxOsAccountNumber);
    ACCOUNT_LOGI("errocde is %{public}d", maxNum->errCode);
    maxNum->status = (maxNum->errCode == 0) ? napi_ok : napi_generic_failure;
}

void QueryMaxNumCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    QueryMaxNumAsyncContext *maxNum = reinterpret_cast<QueryMaxNumAsyncContext *>(data);
    napi_value queryResult[RESULT_COUNT] = {0};
    queryResult[PARAMZERO] = GetErrorCodeValue(env, maxNum->errCode);
    napi_create_int32(env, maxNum->maxOsAccountNumber, &queryResult[PARAMONE]);
    CBOrPromiseMaxNum(env, maxNum, queryResult[PARAMZERO], queryResult[PARAMONE]);
    napi_delete_async_work(env, maxNum->work);
    delete maxNum;
    maxNum = nullptr;
}

void CBOrPromiseMaxNum(napi_env env, const QueryMaxNumAsyncContext *maxNum, napi_value err, napi_value data)
{
    ACCOUNT_LOGI("enter");
    napi_value args[RESULT_COUNT] = {err, data};
    if (maxNum->deferred) {
        ACCOUNT_LOGI("Promise");
        if (maxNum->status == napi_ok) {
            napi_resolve_deferred(env, maxNum->deferred, args[1]);
        } else {
            napi_reject_deferred(env, maxNum->deferred, args[0]);
        }
    } else {
        ACCOUNT_LOGI("Callback");
        napi_value callback = nullptr;
        napi_get_reference_value(env, maxNum->callbackRef, &callback);
        napi_value returnVal = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, &args[0], &returnVal);
        if (maxNum->callbackRef != nullptr) {
            napi_delete_reference(env, maxNum->callbackRef);
        }
    }
}

napi_value ParseParaIsActived(napi_env env, napi_callback_info cbInfo, IsActivedAsyncContext *isActived)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == 0 && valueType == napi_number) {
            isActived->id = GetIntProperty(env, argv[i]);
        } else if (valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &isActived->callbackRef);
            break;
        } else {
            ACCOUNT_LOGE("Type matching failed");
            return nullptr;
        }
    }
    return WrapVoidToJS(env);
}

void IsActivedExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    IsActivedAsyncContext *isActived = reinterpret_cast<IsActivedAsyncContext *>(data);
    isActived->errCode = OsAccountManager::IsOsAccountActived(isActived->id, isActived->isOsAccountActived);
    ACCOUNT_LOGI("errocde is %{public}d", isActived->errCode);
    isActived->status = (isActived->errCode == 0) ? napi_ok : napi_generic_failure;
}

void IsActivedCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    IsActivedAsyncContext *isActived = reinterpret_cast<IsActivedAsyncContext *>(data);
    napi_value result[RESULT_COUNT] = {0};
    result[PARAMZERO] = GetErrorCodeValue(env, isActived->errCode);
    napi_get_boolean(env, isActived->isOsAccountActived, &result[PARAMONE]);
    CBOrPromiseIsActived(env, isActived, result[PARAMZERO], result[PARAMONE]);
    napi_delete_async_work(env, isActived->work);
    delete isActived;
    isActived = nullptr;
}

void CBOrPromiseIsActived(napi_env env, const IsActivedAsyncContext *isActived, napi_value err, napi_value data)
{
    ACCOUNT_LOGI("enter");
    napi_value args[RESULT_COUNT] = {err, data};
    if (isActived->deferred) {
        ACCOUNT_LOGI("Promise");
        if (isActived->status == napi_ok) {
            napi_resolve_deferred(env, isActived->deferred, args[1]);
        } else {
            napi_reject_deferred(env, isActived->deferred, args[0]);
        }
    } else {
        ACCOUNT_LOGI("Callback");
        napi_value callback = nullptr;
        napi_get_reference_value(env, isActived->callbackRef, &callback);
        napi_value returnVal = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, &args[0], &returnVal);
        if (isActived->callbackRef != nullptr) {
            napi_delete_reference(env, isActived->callbackRef);
        }
    }
}

napi_value ParseParaIsEnable(napi_env env, napi_callback_info cbInfo, IsConEnableAsyncContext *isEnable)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == 0 && valueType == napi_number) {
            isEnable->id = GetIntProperty(env, argv[i]);
        } else if (i == 1 && valueType == napi_string) {
            isEnable->constraint = GetStringProperty(env, argv[i]);
        } else if (valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &isEnable->callbackRef);
            break;
        } else {
            ACCOUNT_LOGE("Type matching failed");
            return nullptr;
        }
    }
    return WrapVoidToJS(env);
}

void IsEnableExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    IsConEnableAsyncContext *isEnable = reinterpret_cast<IsConEnableAsyncContext *>(data);
    isEnable->errCode =
        OsAccountManager::IsOsAccountConstraintEnable(isEnable->id, isEnable->constraint, isEnable->isConsEnable);
    ACCOUNT_LOGI("errocde is %{public}d", isEnable->errCode);
    isEnable->status = (isEnable->errCode == 0) ? napi_ok : napi_generic_failure;
}

void IsEnableCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    IsConEnableAsyncContext *isEnable = reinterpret_cast<IsConEnableAsyncContext *>(data);
    napi_value result[RESULT_COUNT] = {0};
    result[PARAMZERO] = GetErrorCodeValue(env, isEnable->errCode);
    napi_get_boolean(env, isEnable->isConsEnable, &result[PARAMONE]);
    CBOrPromiseIsEnable(env, isEnable, result[PARAMZERO], result[PARAMONE]);
    napi_delete_async_work(env, isEnable->work);
    delete isEnable;
    isEnable = nullptr;
}

void CBOrPromiseIsEnable(napi_env env, const IsConEnableAsyncContext *isEnable, napi_value err, napi_value data)
{
    ACCOUNT_LOGI("enter");
    napi_value args[RESULT_COUNT] = {err, data};
    if (isEnable->deferred) {
        ACCOUNT_LOGI("Promise");
        if (isEnable->status == napi_ok) {
            napi_resolve_deferred(env, isEnable->deferred, args[1]);
        } else {
            napi_reject_deferred(env, isEnable->deferred, args[0]);
        }
    } else {
        ACCOUNT_LOGI("Callback");
        napi_value callback = nullptr;
        napi_get_reference_value(env, isEnable->callbackRef, &callback);
        napi_value returnVal = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, &args[0], &returnVal);
        if (isEnable->callbackRef != nullptr) {
            napi_delete_reference(env, isEnable->callbackRef);
        }
    }
}

void ParseParaGetType(napi_env env, napi_callback_info cbInfo, GetTypeAsyncContext *getType)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[0], &valueType);
    if (valueType == napi_function) {
        napi_create_reference(env, argv[0], 1, &getType->callbackRef);
    } else {
        ACCOUNT_LOGE("Type matching failed");
    }
}

void GetTypeExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    GetTypeAsyncContext *getType = reinterpret_cast<GetTypeAsyncContext *>(data);
    getType->errCode = OsAccountManager::GetOsAccountTypeFromProcess(getType->type);
    ACCOUNT_LOGI("errocde is %{public}d", getType->errCode);
    getType->status = (getType->errCode == 0) ? napi_ok : napi_generic_failure;
}

void GetTypeCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    GetTypeAsyncContext *getType = reinterpret_cast<GetTypeAsyncContext *>(data);
    napi_value result[RESULT_COUNT] = {0};
    napi_value jsType = nullptr;
    int cType = static_cast<int>(getType->type);
    result[PARAMZERO] = GetErrorCodeValue(env, getType->errCode);
    napi_create_object(env, &result[PARAMONE]);
    napi_create_int32(env, cType, &jsType);

    switch (cType) {
        case PARAMZERO:
            napi_set_named_property(env, result[PARAMONE], "ADMIN", jsType);
            break;
        case PARAMONE:
            napi_set_named_property(env, result[PARAMONE], "NORMAL", jsType);
            break;
        case PARAMTWO:
            napi_set_named_property(env, result[PARAMONE], "GUEST", jsType);
            break;
        default:
            ACCOUNT_LOGI("cType %{public}d is an invalid value", cType);
            break;
    }
    CBOrPromiseGetType(env, getType, result[PARAMZERO], result[PARAMONE]);
    napi_delete_async_work(env, getType->work);
    delete getType;
    getType = nullptr;
}

void CBOrPromiseGetType(napi_env env, const GetTypeAsyncContext *getType, napi_value err, napi_value data)
{
    ACCOUNT_LOGI("enter");
    napi_value args[RESULT_COUNT] = {err, data};
    if (getType->deferred) {
        ACCOUNT_LOGI("Promise");
        if (getType->status == napi_ok) {
            napi_resolve_deferred(env, getType->deferred, args[1]);
        } else {
            napi_reject_deferred(env, getType->deferred, args[0]);
        }
    } else {
        ACCOUNT_LOGI("Callback");
        napi_value callback = nullptr;
        napi_get_reference_value(env, getType->callbackRef, &callback);
        napi_value returnVal = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, &args[0], &returnVal);
        if (getType->callbackRef != nullptr) {
            napi_delete_reference(env, getType->callbackRef);
        }
    }
}

void ParseParaIsMultiEn(napi_env env, napi_callback_info cbInfo, IsMultiEnAsyncContext *multiEn)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[0], &valueType);
    if (valueType == napi_function) {
        napi_create_reference(env, argv[0], 1, &multiEn->callbackRef);
    } else {
        ACCOUNT_LOGE("Type matching failed");
    }
}

void IsMultiEnExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    IsMultiEnAsyncContext *multiEn = reinterpret_cast<IsMultiEnAsyncContext *>(data);
    multiEn->errCode = OsAccountManager::IsMultiOsAccountEnable(multiEn->isMultiOAEnable);
    ACCOUNT_LOGI("errocde is %{public}d", multiEn->errCode);
    multiEn->status = (multiEn->errCode == 0) ? napi_ok : napi_generic_failure;
}

void IsMultiEnCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    IsMultiEnAsyncContext *multiEn = reinterpret_cast<IsMultiEnAsyncContext *>(data);
    napi_value result[RESULT_COUNT] = {0};
    result[PARAMZERO] = GetErrorCodeValue(env, multiEn->errCode);
    napi_get_boolean(env, multiEn->isMultiOAEnable, &result[PARAMONE]);
    CBOrPromiseIsMultiEn(env, multiEn, result[PARAMZERO], result[PARAMONE]);
    napi_delete_async_work(env, multiEn->work);
    delete multiEn;
    multiEn = nullptr;
}

void CBOrPromiseIsMultiEn(napi_env env, const IsMultiEnAsyncContext *multiEn, napi_value err, napi_value data)
{
    ACCOUNT_LOGI("enter");
    napi_value args[RESULT_COUNT] = {err, data};
    if (multiEn->deferred) {
        ACCOUNT_LOGI("Promise");
        if (multiEn->status == napi_ok) {
            napi_resolve_deferred(env, multiEn->deferred, args[1]);
        } else {
            napi_reject_deferred(env, multiEn->deferred, args[0]);
        }
    } else {
        ACCOUNT_LOGI("Callback");
        napi_value callback = nullptr;
        napi_get_reference_value(env, multiEn->callbackRef, &callback);
        napi_value returnVal = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, &args[0], &returnVal);
        if (multiEn->callbackRef != nullptr) {
            napi_delete_reference(env, multiEn->callbackRef);
        }
    }
}

napi_value ParseParaIsVerified(napi_env env, napi_callback_info cbInfo, IsVerifiedAsyncContext *isVerified)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == 0 && valueType == napi_number) {
            isVerified->id = GetIntProperty(env, argv[i]);
        } else if (i == 0 && valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &isVerified->callbackRef);
            break;
        } else if (i == 1 && valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &isVerified->callbackRef);
            break;
        } else {
            ACCOUNT_LOGE("Type matching failed");
            return nullptr;
        }
    }
    return WrapVoidToJS(env);
}

void IsVerifiedExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    IsVerifiedAsyncContext *isVerified = reinterpret_cast<IsVerifiedAsyncContext *>(data);
    isVerified->errCode = OsAccountManager::IsOsAccountVerified(isVerified->id, isVerified->isTestOA);
    ACCOUNT_LOGI("errocde is %{public}d", isVerified->errCode);
    isVerified->status = (isVerified->errCode == 0) ? napi_ok : napi_generic_failure;
}

void IsVerifiedCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    IsVerifiedAsyncContext *isVerified = reinterpret_cast<IsVerifiedAsyncContext *>(data);
    napi_value result[RESULT_COUNT] = {0};
    result[PARAMZERO] = GetErrorCodeValue(env, isVerified->errCode);
    napi_get_boolean(env, isVerified->isTestOA, &result[PARAMONE]);
    CBOrPromiseIsVerified(env, isVerified, result[PARAMZERO], result[PARAMONE]);
    napi_delete_async_work(env, isVerified->work);
    delete isVerified;
    isVerified = nullptr;
}

void CBOrPromiseIsVerified(napi_env env, const IsVerifiedAsyncContext *isVerified, napi_value err, napi_value data)
{
    ACCOUNT_LOGI("enter");
    napi_value args[RESULT_COUNT] = {err, data};
    if (isVerified->deferred) {
        ACCOUNT_LOGI("Promise");
        if (isVerified->status == napi_ok) {
            napi_resolve_deferred(env, isVerified->deferred, args[1]);
        } else {
            napi_reject_deferred(env, isVerified->deferred, args[0]);
        }
    } else {
        ACCOUNT_LOGI("Callback");
        napi_value callback = nullptr;
        napi_get_reference_value(env, isVerified->callbackRef, &callback);
        napi_value returnVal = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, &args[0], &returnVal);
        if (isVerified->callbackRef != nullptr) {
            napi_delete_reference(env, isVerified->callbackRef);
        }
    }
}

napi_value ParseParaSerialNumId(napi_env env, napi_callback_info cbInfo, GetSerialNumIdCBInfo *serialNumId)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == 0 && valueType == napi_number) {
            serialNumId->serialNumber = GetLongIntProperty(env, argv[i]);
        } else if (valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &serialNumId->callbackRef);
            break;
        } else {
            ACCOUNT_LOGE("Type matching failed");
            return nullptr;
        }
    }
    return WrapVoidToJS(env);
}

void SerialNumIdExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    GetSerialNumIdCBInfo *serialNumId = reinterpret_cast<GetSerialNumIdCBInfo *>(data);
    serialNumId->errCode =
        OsAccountManager::GetOsAccountLocalIdBySerialNumber(serialNumId->serialNumber, serialNumId->id);
    ACCOUNT_LOGI("errocde is %{public}d", serialNumId->errCode);
    serialNumId->status = (serialNumId->errCode == 0) ? napi_ok : napi_generic_failure;
}

void SerialNumIdCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    GetSerialNumIdCBInfo *serialNumId = reinterpret_cast<GetSerialNumIdCBInfo *>(data);
    napi_value result[RESULT_COUNT] = {0};
    result[PARAMZERO] = GetErrorCodeValue(env, serialNumId->errCode);
    napi_create_int32(env, serialNumId->id, &result[PARAMONE]);
    CBOrPromiseSerialNum(env, serialNumId, result[PARAMZERO], result[PARAMONE]);
    napi_delete_async_work(env, serialNumId->work);
    delete serialNumId;
    serialNumId = nullptr;
}

void CBOrPromiseSerialNum(napi_env env, const GetSerialNumIdCBInfo *serialNumId, napi_value err, napi_value data)
{
    ACCOUNT_LOGI("enter");
    napi_value args[RESULT_COUNT] = {err, data};
    if (serialNumId->deferred) {
        ACCOUNT_LOGI("Promise");
        if (serialNumId->status == napi_ok) {
            napi_resolve_deferred(env, serialNumId->deferred, args[1]);
        } else {
            napi_reject_deferred(env, serialNumId->deferred, args[0]);
        }
    } else {
        ACCOUNT_LOGI("Callback");
        napi_value callback = nullptr;
        napi_get_reference_value(env, serialNumId->callbackRef, &callback);
        napi_value returnVal = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, &args[0], &returnVal);
        if (serialNumId->callbackRef != nullptr) {
            napi_delete_reference(env, serialNumId->callbackRef);
        }
    }
}

napi_value ParseParaGetSerialNum(napi_env env, napi_callback_info cbInfo, GetSerialNumForOAInfo *getSerialNum)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == 0 && valueType == napi_number) {
            getSerialNum->id = GetIntProperty(env, argv[i]);
        } else if (valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &getSerialNum->callbackRef);
            break;
        } else {
            ACCOUNT_LOGE("Type matching failed");
            return nullptr;
        }
    }
    return WrapVoidToJS(env);
}

void GetSerialNumExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    GetSerialNumForOAInfo *getSerialNum = reinterpret_cast<GetSerialNumForOAInfo *>(data);
    getSerialNum->errCode =
        OsAccountManager::GetSerialNumberByOsAccountLocalId(getSerialNum->id, getSerialNum->serialNum);
    ACCOUNT_LOGI("errocde is %{public}d", getSerialNum->errCode);
    getSerialNum->status = (getSerialNum->errCode == 0) ? napi_ok : napi_generic_failure;
}

void GetSerialNumCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    GetSerialNumForOAInfo *getSerialNum = reinterpret_cast<GetSerialNumForOAInfo *>(data);
    napi_value result[RESULT_COUNT] = {0};
    result[PARAMZERO] = GetErrorCodeValue(env, getSerialNum->errCode);
    napi_create_int64(env, getSerialNum->serialNum, &result[PARAMONE]);
    CBOrPromiseGetSerialNum(env, getSerialNum, result[PARAMZERO], result[PARAMONE]);
    napi_delete_async_work(env, getSerialNum->work);
    delete getSerialNum;
    getSerialNum = nullptr;
}

void CBOrPromiseGetSerialNum(napi_env env, const GetSerialNumForOAInfo *getSerialNum, napi_value err, napi_value data)
{
    ACCOUNT_LOGI("enter");
    napi_value args[RESULT_COUNT] = {err, data};
    if (getSerialNum->deferred) {
        ACCOUNT_LOGI("Promise");
        if (getSerialNum->status == napi_ok) {
            napi_resolve_deferred(env, getSerialNum->deferred, args[1]);
        } else {
            napi_reject_deferred(env, getSerialNum->deferred, args[0]);
        }
    } else {
        ACCOUNT_LOGI("Callback");
        napi_value callback = nullptr;
        napi_get_reference_value(env, getSerialNum->callbackRef, &callback);
        napi_value returnVal = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, &args[0], &returnVal);
        if (getSerialNum->callbackRef != nullptr) {
            napi_delete_reference(env, getSerialNum->callbackRef);
        }
    }
}

void ParseParaIsTestOA(napi_env env, napi_callback_info cbInfo, IsTestOAInfo *isTest)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[0], &valueType);
    if (valueType == napi_function) {
        napi_create_reference(env, argv[0], 1, &isTest->callbackRef);
    } else {
        ACCOUNT_LOGE("Type matching failed");
    }
}

void ParseParaIsMainOA(napi_env env, napi_callback_info cbInfo, IsMainOAInfo *isMain)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[0], &valueType);
    if (valueType == napi_function) {
        napi_create_reference(env, argv[0], 1, &isMain->callbackRef);
    } else {
        ACCOUNT_LOGE("Type matching failed");
    }
}

void CBOrPromiseIsTestOA(napi_env env, const IsTestOAInfo *isTest, napi_value err, napi_value data)
{
    ACCOUNT_LOGI("enter");
    napi_value args[RESULT_COUNT] = {err, data};
    if (isTest->deferred) {
        ACCOUNT_LOGI("Promise");
        if (isTest->status == napi_ok) {
            napi_resolve_deferred(env, isTest->deferred, args[1]);
        } else {
            napi_reject_deferred(env, isTest->deferred, args[0]);
        }
    } else {
        ACCOUNT_LOGI("Callback");
        napi_value callback = nullptr;
        napi_get_reference_value(env, isTest->callbackRef, &callback);
        napi_value returnVal = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, &args[0], &returnVal);
        if (isTest->callbackRef != nullptr) {
            napi_delete_reference(env, isTest->callbackRef);
        }
    }
}

void CBOrPromiseIsMainOA(napi_env env, const IsMainOAInfo *isMain, napi_value err, napi_value data)
{
    ACCOUNT_LOGI("enter");
    napi_value args[RESULT_COUNT] = {err, data};
    if (isMain->deferred) {
        ACCOUNT_LOGI("Promise");
        if (isMain->status == napi_ok) {
            napi_resolve_deferred(env, isMain->deferred, args[1]);
        } else {
            napi_reject_deferred(env, isMain->deferred, args[0]);
        }
    } else {
        ACCOUNT_LOGI("Callback");
        napi_value callback = nullptr;
        napi_get_reference_value(env, isMain->callbackRef, &callback);
        napi_value returnVal = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, &args[0], &returnVal);
        if (isMain->callbackRef != nullptr) {
            napi_delete_reference(env, isMain->callbackRef);
        }
    }
}

napi_value ParseParaToSubscriber(const napi_env &env, const napi_value (&argv)[ARGS_SIZE_THREE], napi_ref &callback,
    OS_ACCOUNT_SUBSCRIBE_TYPE &onType, std::string &onName)
{
    ACCOUNT_LOGI("enter");

    // argv[0] type: 'activate' | 'activating'
    napi_valuetype valuetype = napi_undefined;
    napi_typeof(env, argv[0], &valuetype);
    if (valuetype == napi_string) {
        std::string type = GetStringProperty(env, argv[0]);
        if (type == "activate") {
            onType = OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVED;
        } else if (type == "activating") {
            onType = OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATING;
        } else {
            ACCOUNT_LOGI("Wrong type string.");
            return nullptr;
        }
    } else {
        ACCOUNT_LOGE("Type matching failed");
        return nullptr;
    }

    // argv[1] name: string
    napi_typeof(env, argv[1], &valuetype);
    if (valuetype == napi_string) {
        onName = GetStringProperty(env, argv[1]);
        if (onName.size() == 0 || onName.size() > MAX_SUBSCRIBER_NAME_LEN) {
            ACCOUNT_LOGI("Subscriber name invalid");
            return nullptr;
        }
    } else {
        ACCOUNT_LOGE("Type matching failed");
        return nullptr;
    }

    // argv[2] callback
    napi_typeof(env, argv[PARAMTWO], &valuetype);
    if (valuetype == napi_function) {
        napi_create_reference(env, argv[PARAMTWO], 1, &callback);
    } else {
        ACCOUNT_LOGE("Type matching failed");
        return nullptr;
    }

    return WrapVoidToJS(env);
}

void SubscribeExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    SubscribeCBInfo *subscribeCBInfo = reinterpret_cast<SubscribeCBInfo *>(data);
    subscribeCBInfo->subscriber->SetEnv(env);
    subscribeCBInfo->subscriber->SetCallbackRef(subscribeCBInfo->callbackRef);
    int errCode = OsAccountManager::SubscribeOsAccount(subscribeCBInfo->subscriber);
    ACCOUNT_LOGI("errocde is %{public}d", errCode);
}

void SubscribeCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete.");
    SubscribeCBInfo *subscribeCBInfo = reinterpret_cast<SubscribeCBInfo *>(data);
    napi_delete_async_work(env, subscribeCBInfo->work);
}

napi_value ParseParaToUnsubscriber(const napi_env &env, const size_t &argc, const napi_value (&argv)[ARGS_SIZE_THREE],
    napi_ref &callback, OS_ACCOUNT_SUBSCRIBE_TYPE &offType, std::string &offName)
{
    ACCOUNT_LOGI("enter");

    // argv[0] type: 'activate' | 'activating'
    napi_valuetype valuetype = napi_undefined;
    napi_typeof(env, argv[0], &valuetype);
    if (valuetype == napi_string) {
        std::string type = GetStringProperty(env, argv[0]);
        if (type == "activate") {
            offType = OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVED;
        } else if (type == "activating") {
            offType = OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATING;
        } else {
            ACCOUNT_LOGI("Wrong type string.");
            return nullptr;
        }
    } else {
        ACCOUNT_LOGE("Type matching failed");
        return nullptr;
    }

    // argv[1] name: string
    napi_typeof(env, argv[1], &valuetype);
    if (valuetype == napi_string) {
        offName = GetStringProperty(env, argv[1]);
        if (offName.size() == 0 || offName.size() > MAX_SUBSCRIBER_NAME_LEN) {
            ACCOUNT_LOGI("Unsubscriber name invalid");
            return nullptr;
        }
    } else {
        ACCOUNT_LOGE("Type matching failed");
        return nullptr;
    }

    // argv[2]:callback
    if (argc >= ARGS_SIZE_THREE) {
        napi_typeof(env, argv[PARAMTWO], &valuetype);
        if (valuetype == napi_function) {
            napi_create_reference(env, argv[PARAMTWO], 1, &callback);
        } else {
            ACCOUNT_LOGE("Type matching failed");
            return nullptr;
        }
    }

    return WrapVoidToJS(env);
}
}  // namespace AccountJsKit
}  // namespace OHOS