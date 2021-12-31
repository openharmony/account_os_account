/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

void ParseParaQueryOAByIdCB(napi_env env, napi_callback_info cbInfo, QueryOAByIdAsyncContext *queryOAByIdCB)
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
        }
    }
}

void QueryOAByIdExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    QueryOAByIdAsyncContext *queryOAByIdCB = (QueryOAByIdAsyncContext *)data;
    queryOAByIdCB->errCode = OsAccountManager::QueryOsAccountById(queryOAByIdCB->id, queryOAByIdCB->osAccountInfos);
    ACCOUNT_LOGI("errcode is %{public}d", queryOAByIdCB->errCode);
    queryOAByIdCB->status = queryOAByIdCB->errCode == 0 ? napi_ok : napi_generic_failure;
}

void QueryOAByIdCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    QueryOAByIdAsyncContext *queryOAByIdCB = (QueryOAByIdAsyncContext *)data;
    napi_value queryResult[RESULT_COUNT] = {0};
    queryResult[PARAM0] = GetErrorCodeValue(env, queryOAByIdCB->errCode);
    napi_create_object(env, &queryResult[PARAM1]);
    GetOACBInfoToJs(env, queryOAByIdCB->osAccountInfos, queryResult[PARAM1]);
    CBOrPromiseToQueryOAById(env, queryOAByIdCB, queryResult[PARAM0], queryResult[PARAM1]);
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
        std::map<std::string, std::string> scalableData = {};
        napi_value scalable = nullptr;
        napi_create_object(env, &scalable);
        for (const auto &[key, item] : scalableData) {
            napi_value jsValue = nullptr;
            napi_create_string_utf8(env, item.c_str(), item.size(), &jsValue);
            napi_set_named_property(env, scalable, key.c_str(), jsValue);
        }
        napi_set_named_property(env, dbInfoToJs, "scalableData", scalable);
    } else {
        napi_get_undefined(env, &dbInfoToJs);
    }
    napi_set_named_property(env, objOAInfo, "distributedInfo", dbInfoToJs);
}

void MakeArrayToJs(napi_env env, const std::vector<std::string> &constraints, napi_value jsArray)
{
    ACCOUNT_LOGI("enter");

    int32_t index = 0;

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

void ParseParaRemoveOACB(napi_env env, napi_callback_info cbInfo, RemoveOAAsyncContext *removeOACB)
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
        }
    }
}

void RemoveOAExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    RemoveOAAsyncContext *removeOACB = (RemoveOAAsyncContext *)data;
    removeOACB->errCode = OsAccountManager::RemoveOsAccount(removeOACB->id);
    ACCOUNT_LOGI("errcode is %{public}d", removeOACB->errCode);
    removeOACB->status = removeOACB->errCode == 0 ? napi_ok : napi_generic_failure;
}

void RemoveOACallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    RemoveOAAsyncContext *removeOACB = (RemoveOAAsyncContext *)data;
    napi_value rmResult[RESULT_COUNT] = {0};
    rmResult[PARAM0] = GetErrorCodeValue(env, removeOACB->errCode);
    napi_get_undefined(env, &rmResult[PARAM1]);
    CBOrPromiseToRemoveOA(env, removeOACB, rmResult[PARAM0], rmResult[PARAM1]);
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

void ParseParaSetOAName(napi_env env, napi_callback_info cbInfo, SetOANameAsyncContext *setOANameCB)
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
        }
    }
}

void SetOANameExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    SetOANameAsyncContext *setOANameCB = (SetOANameAsyncContext *)data;
    setOANameCB->errCode = OsAccountManager::SetOsAccountName(setOANameCB->id, setOANameCB->name);
    ACCOUNT_LOGI("errcode is %{public}d", setOANameCB->errCode);
    setOANameCB->status = setOANameCB->errCode == 0 ? napi_ok : napi_generic_failure;
}

void SetOANameCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    SetOANameAsyncContext *setOANameCB = (SetOANameAsyncContext *)data;
    napi_value setNameResult[RESULT_COUNT] = {0};
    setNameResult[PARAM0] = GetErrorCodeValue(env, setOANameCB->errCode);
    napi_get_undefined(env, &setNameResult[PARAM1]);
    CBOrPromiseToSetOAName(env, setOANameCB, setNameResult[PARAM0], setNameResult[PARAM1]);
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
    NAPI_CALL(env, napi_typeof(env, argv[PARAMTHREE], &valueType));
    NAPI_ASSERT(env, valueType == napi_function, "Wrong argument type. Function expected.");
    NAPI_CALL(env, napi_create_reference(env, argv[PARAMTHREE], 1, &setOAConsCB->callbackRef));

    return WrapVoidToJS(env);
}

void SetOAConsExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    SetOAConsAsyncContext *setOAConsCB = (SetOAConsAsyncContext *)data;
    setOAConsCB->errCode =
        OsAccountManager::SetOsAccountConstraints(setOAConsCB->id, setOAConsCB->constraints, setOAConsCB->enable);
    ACCOUNT_LOGI("errcode is %{public}d", setOAConsCB->errCode);
    setOAConsCB->status = setOAConsCB->errCode == 0 ? napi_ok : napi_generic_failure;
}

void SetOAConsCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    SetOAConsAsyncContext *setOAConsCB = (SetOAConsAsyncContext *)data;
    napi_value setConsResult[RESULT_COUNT] = {0};
    setConsResult[PARAM0] = GetErrorCodeValue(env, setOAConsCB->errCode);
    napi_get_undefined(env, &setConsResult[PARAM1]);
    CBOrPromiseToSetOACons(env, setOAConsCB, setConsResult[PARAM0], setConsResult[PARAM1]);
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

void ParseParaActiveOA(napi_env env, napi_callback_info cbInfo, ActivateOAAsyncContext *activeOACB)
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
        }
    }
}

void ActivateOAExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    ActivateOAAsyncContext *activateOACB = (ActivateOAAsyncContext *)data;
    activateOACB->errCode = OsAccountManager::ActivateOsAccount(activateOACB->id);
    ACCOUNT_LOGI("errocde is %{public}d", activateOACB->errCode);
    activateOACB->status = activateOACB->errCode == 0 ? napi_ok : napi_generic_failure;
}

void ActivateOACallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    ActivateOAAsyncContext *activateOA = (ActivateOAAsyncContext *)data;
    napi_value activateResult[RESULT_COUNT] = {0};
    activateResult[PARAM0] = GetErrorCodeValue(env, activateOA->errCode);
    napi_get_undefined(env, &activateResult[PARAM1]);
    CBOrPromiseToActivateOA(env, activateOA, activateResult[PARAM0], activateResult[PARAM1]);
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

void ParseParaCreateOA(napi_env env, napi_callback_info cbInfo, CreateOAAsyncContext *createOACB)
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
        }
    }
}

void CreateOAExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    CreateOAAsyncContext *createOACB = (CreateOAAsyncContext *)data;
    createOACB->errCode =
        OsAccountManager::CreateOsAccount(createOACB->name, createOACB->type, createOACB->osAccountInfos);
    ACCOUNT_LOGI("errocde is %{public}d", createOACB->errCode);
    createOACB->status = createOACB->errCode == 0 ? napi_ok : napi_generic_failure;
}

void CreateOACallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    CreateOAAsyncContext *createOACB = (CreateOAAsyncContext *)data;
    napi_value createResult[RESULT_COUNT] = {0};
    createResult[PARAM0] = GetErrorCodeValue(env, createOACB->errCode);
    napi_create_object(env, &createResult[PARAM1]);
    GetOACBInfoToJs(env, createOACB->osAccountInfos, createResult[PARAM1]);
    CBOrPromiseToCreateOA(env, createOACB, createResult[PARAM0], createResult[PARAM1]);
    napi_delete_async_work(env, createOACB->work);
    delete createOACB;
    createOACB = nullptr;
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
    GetOACountAsyncContext *getOACount = (GetOACountAsyncContext *)data;
    getOACount->errCode = OsAccountManager::GetCreatedOsAccountsCount(getOACount->osAccountsCount);
    ACCOUNT_LOGI("errocde is %{public}d", getOACount->errCode);
    getOACount->status = getOACount->errCode == 0 ? napi_ok : napi_generic_failure;
}

void GetOACountCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    GetOACountAsyncContext *getOACount = (GetOACountAsyncContext *)data;
    napi_value getResult[RESULT_COUNT] = {0};
    getResult[PARAM0] = GetErrorCodeValue(env, getOACount->errCode);
    napi_create_int32(env, getOACount->osAccountsCount, &getResult[PARAM1]);
    CBOrPromiseToGetOACount(env, getOACount, getResult[PARAM0], getResult[PARAM1]);
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
    DbDeviceIdAsyncContext *dbDeviceId = (DbDeviceIdAsyncContext *)data;
    dbDeviceId->errCode = OsAccountManager::GetDistributedVirtualDeviceId(dbDeviceId->deviceId);
    ACCOUNT_LOGI("errocde is %{public}d", dbDeviceId->errCode);
    dbDeviceId->status = dbDeviceId->errCode == 0 ? napi_ok : napi_generic_failure;
}

void DbDeviceIdCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    DbDeviceIdAsyncContext *dbDeviceId = (DbDeviceIdAsyncContext *)data;
    napi_value dbIdResult[RESULT_COUNT] = {0};
    dbIdResult[PARAM0] = GetErrorCodeValue(env, dbDeviceId->errCode);
    napi_create_string_utf8(env, dbDeviceId->deviceId.c_str(), NAPI_AUTO_LENGTH, &dbIdResult[PARAM1]);
    CBOrPromiseToDbDeviceId(env, dbDeviceId, dbIdResult[PARAM0], dbIdResult[PARAM1]);
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

void ParseParaGetAllCons(napi_env env, napi_callback_info cbInfo, GetAllConsAsyncContext *getAllConsCB)
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
        }
    }
}

void GetAllConsExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    GetAllConsAsyncContext *getAllConsCB = (GetAllConsAsyncContext *)data;
    getAllConsCB->errCode = OsAccountManager::GetOsAccountAllConstraints(getAllConsCB->id, getAllConsCB->constraints);
    ACCOUNT_LOGI("errocde is %{public}d", getAllConsCB->errCode);
    getAllConsCB->status = getAllConsCB->errCode == 0 ? napi_ok : napi_generic_failure;
}

void GetAllConsCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    GetAllConsAsyncContext *getAllConsCB = (GetAllConsAsyncContext *)data;
    napi_value getResult[RESULT_COUNT] = {0};
    getResult[PARAM0] = GetErrorCodeValue(env, getAllConsCB->errCode);
    napi_create_array(env, &getResult[PARAM1]);
    GetAllAccountCons(env, getAllConsCB->constraints, getResult[PARAM1]);
    CBOrPromiseToGetAllCons(env, getAllConsCB, getResult[PARAM0], getResult[PARAM1]);
    napi_delete_async_work(env, getAllConsCB->work);
    delete getAllConsCB;
    getAllConsCB = nullptr;
}

void GetAllAccountCons(napi_env env, const std::vector<std::string> &info, napi_value result)
{
    ACCOUNT_LOGI("enter");

    int32_t index = 0;

    for (auto item : info) {
        napi_value consStr = nullptr;
        napi_create_string_utf8(env, item.c_str(), NAPI_AUTO_LENGTH, &consStr);
        napi_set_element(env, result, index, consStr);
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
    GetIdAsyncContext *getIdCB = (GetIdAsyncContext *)data;
    getIdCB->errCode = OsAccountManager::GetOsAccountLocalIdFromProcess(getIdCB->id);
    ACCOUNT_LOGI("errocde is %{public}d", getIdCB->errCode);
    getIdCB->status = getIdCB->errCode == 0 ? napi_ok : napi_generic_failure;
}

void GetProcessIdCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    GetIdAsyncContext *getIdCB = (GetIdAsyncContext *)data;
    napi_value getResult[RESULT_COUNT] = {0};
    getResult[PARAM0] = GetErrorCodeValue(env, getIdCB->errCode);
    napi_create_int32(env, getIdCB->id, &getResult[PARAM1]);
    CBOrPromiseToGetProcessId(env, getIdCB, getResult[PARAM0], getResult[PARAM1]);
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

void ParseParaQueryOA(napi_env env, napi_callback_info cbInfo, QueryCreateOAAsyncContext *queryAllOA)
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

void QueryCreateOAExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    QueryCreateOAAsyncContext *queryAllOA = (QueryCreateOAAsyncContext *)data;
    queryAllOA->errCode = OsAccountManager::QueryAllCreatedOsAccounts(queryAllOA->osAccountInfos);
    ACCOUNT_LOGI("errocde is %{public}d", queryAllOA->errCode);
    queryAllOA->status = queryAllOA->errCode == 0 ? napi_ok : napi_generic_failure;
}

void QueryCreateOACallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    QueryCreateOAAsyncContext *queryAllOA = (QueryCreateOAAsyncContext *)data;
    napi_value queryResult[RESULT_COUNT] = {0};
    queryResult[PARAM0] = GetErrorCodeValue(env, queryAllOA->errCode);
    napi_create_array(env, &queryResult[PARAM1]);
    QueryOAInfoForResult(env, queryAllOA->osAccountInfos, queryResult[PARAM1]);
    CBOrPromiseToQueryOA(env, queryAllOA, queryResult[PARAM0], queryResult[PARAM1]);
    napi_delete_async_work(env, queryAllOA->work);
    delete queryAllOA;
    queryAllOA = nullptr;
}

void QueryOAInfoForResult(napi_env env, const std::vector<OsAccountInfo> &info, napi_value result)
{
    ACCOUNT_LOGI("enter");

    int32_t index = 0;

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

void ParseParaGetPhote(napi_env env, napi_callback_info cbInfo, GetOAPhotoAsyncContext *getPhoto)
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
        }
    }
}

void GetOAPhoteExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    GetOAPhotoAsyncContext *getPhoto = (GetOAPhotoAsyncContext *)data;
    getPhoto->errCode = OsAccountManager::GetOsAccountProfilePhoto(getPhoto->id, getPhoto->photo);
    ACCOUNT_LOGI("errocde is %{public}d", getPhoto->errCode);
    getPhoto->status = getPhoto->errCode == 0 ? napi_ok : napi_generic_failure;
}

void GetOAPhoteCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    GetOAPhotoAsyncContext *getPhoto = (GetOAPhotoAsyncContext *)data;
    napi_value getResult[RESULT_COUNT] = {0};
    getResult[PARAM0] = GetErrorCodeValue(env, getPhoto->errCode);
    napi_create_string_utf8(env, getPhoto->photo.c_str(), NAPI_AUTO_LENGTH, &getResult[PARAM1]);
    CBOrPromiseToGetPhoto(env, getPhoto, getResult[PARAM0], getResult[PARAM1]);
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
    CurrentOAAsyncContext *currentOA = (CurrentOAAsyncContext *)data;
    currentOA->errCode = OsAccountManager::QueryCurrentOsAccount(currentOA->osAccountInfos);
    ACCOUNT_LOGI("errocde is %{public}d", currentOA->errCode);
    currentOA->status = currentOA->errCode == 0 ? napi_ok : napi_generic_failure;
}

void QueryCurrentOACallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    CurrentOAAsyncContext *currentOA = (CurrentOAAsyncContext *)data;
    napi_value queryResult[RESULT_COUNT] = {0};
    queryResult[PARAM0] = GetErrorCodeValue(env, currentOA->errCode);
    napi_create_object(env, &queryResult[PARAM1]);
    GetOACBInfoToJs(env, currentOA->osAccountInfos, queryResult[PARAM1]);
    CBOrPromiseQueryCurrentOA(env, currentOA, queryResult[PARAM0], queryResult[PARAM1]);
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

void ParseParaGetIdByUid(napi_env env, napi_callback_info cbInfo, GetIdByUidAsyncContext *idByUid)
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
        }
    }
}

void GetIdByUidExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    GetIdByUidAsyncContext *idByUid = (GetIdByUidAsyncContext *)data;
    idByUid->errCode = OsAccountManager::GetOsAccountLocalIdFromUid(idByUid->uid, idByUid->id);
    ACCOUNT_LOGI("errocde is %{public}d", idByUid->errCode);
    idByUid->status = idByUid->errCode == 0 ? napi_ok : napi_generic_failure;
}

void GetIdByUidCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    GetIdByUidAsyncContext *idByUid = (GetIdByUidAsyncContext *)data;
    napi_value uidResult[RESULT_COUNT] = {0};
    uidResult[PARAM0] = GetErrorCodeValue(env, idByUid->errCode);
    napi_create_int32(env, idByUid->id, &uidResult[PARAM1]);
    CBOrPromiseGetIdByUid(env, idByUid, uidResult[PARAM0], uidResult[PARAM1]);
    napi_delete_async_work(env, idByUid->work);
    delete idByUid;
    idByUid = nullptr;
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

void ParseParaSetPhoto(napi_env env, napi_callback_info cbInfo, SetOAPhotoAsyncContext *setPhoto)
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
        }
    }
}

void SetPhotoExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    SetOAPhotoAsyncContext *setPhoto = (SetOAPhotoAsyncContext *)data;
    setPhoto->errCode = OsAccountManager::SetOsAccountProfilePhoto(setPhoto->id, setPhoto->photo);
    ACCOUNT_LOGI("errocde is %{public}d", setPhoto->errCode);
    setPhoto->status = setPhoto->errCode == 0 ? napi_ok : napi_generic_failure;
}

void SetPhotoCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    SetOAPhotoAsyncContext *setPhoto = (SetOAPhotoAsyncContext *)data;
    napi_value setResult[RESULT_COUNT] = {0};
    setResult[PARAM0] = GetErrorCodeValue(env, setPhoto->errCode);
    napi_get_undefined(env, &setResult[PARAM1]);
    CBOrPromiseSetPhoto(env, setPhoto, setResult[PARAM0], setResult[PARAM1]);
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
    QueryMaxNumAsyncContext *maxNum = (QueryMaxNumAsyncContext *)data;
    maxNum->errCode = OsAccountManager::QueryMaxOsAccountNumber(maxNum->maxOsAccountNumber);
    ACCOUNT_LOGI("errocde is %{public}d", maxNum->errCode);
    maxNum->status = maxNum->errCode == 0 ? napi_ok : napi_generic_failure;
}

void QueryMaxNumCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    QueryMaxNumAsyncContext *maxNum = (QueryMaxNumAsyncContext *)data;
    napi_value queryResult[RESULT_COUNT] = {0};
    queryResult[PARAM0] = GetErrorCodeValue(env, maxNum->errCode);
    napi_create_int32(env, maxNum->maxOsAccountNumber, &queryResult[PARAM1]);
    CBOrPromiseMaxNum(env, maxNum, queryResult[PARAM0], queryResult[PARAM1]);
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

void ParseParaIsActived(napi_env env, napi_callback_info cbInfo, IsActivedAsyncContext *isActived)
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
        }
    }
}

void IsActivedExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    IsActivedAsyncContext *isActived = (IsActivedAsyncContext *)data;
    isActived->errCode = OsAccountManager::IsOsAccountActived(isActived->id, isActived->isOsAccountActived);
    ACCOUNT_LOGI("errocde is %{public}d", isActived->errCode);
    isActived->status = isActived->errCode == 0 ? napi_ok : napi_generic_failure;
}

void IsActivedCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    IsActivedAsyncContext *isActived = (IsActivedAsyncContext *)data;
    napi_value result[RESULT_COUNT] = {0};
    result[PARAM0] = GetErrorCodeValue(env, isActived->errCode);
    napi_get_boolean(env, isActived->isOsAccountActived, &result[PARAM1]);
    CBOrPromiseIsActived(env, isActived, result[PARAM0], result[PARAM1]);
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

void ParseParaIsEnable(napi_env env, napi_callback_info cbInfo, IsConEnableAsyncContext *isEnable)
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
        }
    }
}

void IsEnableExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    IsConEnableAsyncContext *isEnable = (IsConEnableAsyncContext *)data;
    isEnable->errCode =
        OsAccountManager::IsOsAccountConstraintEnable(isEnable->id, isEnable->constraint, isEnable->isConsEnable);
    ACCOUNT_LOGI("errocde is %{public}d", isEnable->errCode);
    isEnable->status = isEnable->errCode == 0 ? napi_ok : napi_generic_failure;
}

void IsEnableCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    IsConEnableAsyncContext *isEnable = (IsConEnableAsyncContext *)data;
    napi_value result[RESULT_COUNT] = {0};
    result[PARAM0] = GetErrorCodeValue(env, isEnable->errCode);
    napi_get_boolean(env, isEnable->isConsEnable, &result[PARAM1]);
    CBOrPromiseIsEnable(env, isEnable, result[PARAM0], result[PARAM1]);
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
    GetTypeAsyncContext *getType = (GetTypeAsyncContext *)data;
    getType->errCode = OsAccountManager::GetOsAccountTypeFromProcess(getType->type);
    ACCOUNT_LOGI("errocde is %{public}d", getType->errCode);
    getType->status = getType->errCode == 0 ? napi_ok : napi_generic_failure;
}

void GetTypeCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    GetTypeAsyncContext *getType = (GetTypeAsyncContext *)data;
    napi_value result[RESULT_COUNT] = {0};
    napi_value jsType = nullptr;
    int cType = static_cast<int>(getType->type);
    result[PARAM0] = GetErrorCodeValue(env, getType->errCode);
    napi_create_object(env, &result[PARAM1]);
    napi_create_int32(env, cType, &jsType);

    switch (cType) {
        case PARAMZERO:
            napi_set_named_property(env, result[PARAM1], "ADMIN", jsType);
            break;
        case PARAMONE:
            napi_set_named_property(env, result[PARAM1], "NORMAL", jsType);
            break;
        case PARAMTWO:
            napi_set_named_property(env, result[PARAM1], "GUEST", jsType);
            break;
        default:
            ACCOUNT_LOGI("cType %{public}d is an invalid value", cType);
            break;
    }
    CBOrPromiseGetType(env, getType, result[PARAM0], result[PARAM1]);
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
    IsMultiEnAsyncContext *multiEn = (IsMultiEnAsyncContext *)data;
    multiEn->errCode = OsAccountManager::IsMultiOsAccountEnable(multiEn->isMultiOAEnable);
    ACCOUNT_LOGI("errocde is %{public}d", multiEn->errCode);
    multiEn->status = multiEn->errCode == 0 ? napi_ok : napi_generic_failure;
}

void IsMultiEnCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    IsMultiEnAsyncContext *multiEn = (IsMultiEnAsyncContext *)data;
    napi_value result[RESULT_COUNT] = {0};
    result[PARAM0] = GetErrorCodeValue(env, multiEn->errCode);
    napi_get_boolean(env, multiEn->isMultiOAEnable, &result[PARAM1]);
    CBOrPromiseIsMultiEn(env, multiEn, result[PARAM0], result[PARAM1]);
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

void ParseParaIsVerified(napi_env env, napi_callback_info cbInfo, IsVerifiedAsyncContext *isVerified)
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
        }
    }
}

void IsVerifiedExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    IsVerifiedAsyncContext *isVerified = (IsVerifiedAsyncContext *)data;
    isVerified->errCode = OsAccountManager::IsOsAccountVerified(isVerified->id, isVerified->isTestOA);
    ACCOUNT_LOGI("errocde is %{public}d", isVerified->errCode);
    isVerified->status = isVerified->errCode == 0 ? napi_ok : napi_generic_failure;
}

void IsVerifiedCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    IsVerifiedAsyncContext *isVerified = (IsVerifiedAsyncContext *)data;
    napi_value result[RESULT_COUNT] = {0};
    result[PARAM0] = GetErrorCodeValue(env, isVerified->errCode);
    napi_get_boolean(env, isVerified->isTestOA, &result[PARAM1]);
    CBOrPromiseIsVerified(env, isVerified, result[PARAM0], result[PARAM1]);
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

void ParseParaSerialNumId(napi_env env, napi_callback_info cbInfo, GetSerialNumIdCBInfo *serialNumId)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == 0 && valueType == napi_string) {
            serialNumId->serialNumber = GetLongIntProperty(env, argv[i]);
        } else if (valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &serialNumId->callbackRef);
            break;
        } else {
            ACCOUNT_LOGE("Type matching failed");
        }
    }
}

void SerialNumIdExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    GetSerialNumIdCBInfo *serialNumId = (GetSerialNumIdCBInfo *)data;
    serialNumId->errCode =
        OsAccountManager::GetOsAccountLocalIdBySerialNumber(serialNumId->serialNumber, serialNumId->id);
    ACCOUNT_LOGI("errocde is %{public}d", serialNumId->errCode);
    serialNumId->status = serialNumId->errCode == 0 ? napi_ok : napi_generic_failure;
}

void SerialNumIdCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    GetSerialNumIdCBInfo *serialNumId = (GetSerialNumIdCBInfo *)data;
    napi_value result[RESULT_COUNT] = {0};
    result[PARAM0] = GetErrorCodeValue(env, serialNumId->errCode);
    napi_create_int32(env, serialNumId->id, &result[PARAM1]);
    CBOrPromiseSerialNum(env, serialNumId, result[PARAM0], result[PARAM1]);
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

void ParseParaGetSerialNum(napi_env env, napi_callback_info cbInfo, GetSerialNumForOAInfo *getSerialNum)
{
    ACCOUNT_LOGI("enter");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == 0 && valueType == napi_string) {
            getSerialNum->id = GetIntProperty(env, argv[i]);
        } else if (valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &getSerialNum->callbackRef);
            break;
        } else {
            ACCOUNT_LOGE("Type matching failed");
        }
    }
}

void GetSerialNumExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    GetSerialNumForOAInfo *getSerialNum = (GetSerialNumForOAInfo *)data;
    getSerialNum->errCode =
        OsAccountManager::GetSerialNumberByOsAccountLocalId(getSerialNum->id, getSerialNum->serialNum);
    ACCOUNT_LOGI("errocde is %{public}d", getSerialNum->errCode);
    getSerialNum->status = getSerialNum->errCode == 0 ? napi_ok : napi_generic_failure;
}

void GetSerialNumCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete");
    GetSerialNumForOAInfo *getSerialNum = (GetSerialNumForOAInfo *)data;
    napi_value result[RESULT_COUNT] = {0};
    result[PARAM0] = GetErrorCodeValue(env, getSerialNum->errCode);
    napi_create_int64(env, getSerialNum->serialNum, &result[PARAM1]);
    CBOrPromiseGetSerialNum(env, getSerialNum, result[PARAM0], result[PARAM1]);
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

void ParseParaToSubscriber(const napi_env &env, const napi_value (&argv)[ARGS_SIZE_THREE], napi_ref &callback,
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
        }
    } else {
        ACCOUNT_LOGE("Type matching failed");
    }

    // argv[1] name: string
    napi_typeof(env, argv[1], &valuetype);
    if (valuetype == napi_string) {
        onName = GetStringProperty(env, argv[1]);
        if (onName.size() == 0 || onName.size() > MAX_SUBSCRIBER_NAME_LEN) {
            return;
        }
    } else {
        ACCOUNT_LOGE("Type matching failed");
    }

    // argv[2] callback
    napi_typeof(env, argv[PARAMTWO], &valuetype);
    if (valuetype == napi_function) {
        napi_create_reference(env, argv[PARAMTWO], 1, &callback);
    } else {
        ACCOUNT_LOGE("Type matching failed");
    }
}

void SubscribeExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work running");
    SubscribeCBInfo *subscribeCBInfo = (SubscribeCBInfo *)data;
    subscribeCBInfo->subscriber->SetEnv(env);
    subscribeCBInfo->subscriber->SetCallbackRef(subscribeCBInfo->callbackRef);
    int errCode = OsAccountManager::SubscribeOsAccount(subscribeCBInfo->subscriber);
    ACCOUNT_LOGI("errocde is %{public}d", errCode);
}

void SubscribeCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGI("napi_create_async_work complete.");
    SubscribeCBInfo *subscribeCBInfo = (SubscribeCBInfo *)data;
    napi_delete_async_work(env, subscribeCBInfo->work);
}

void ParseParaToUnsubscriber(const napi_env &env, const size_t &argc, const napi_value (&argv)[ARGS_SIZE_THREE],
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
        }
    } else {
        ACCOUNT_LOGE("Type matching failed");
    }

    // argv[1] name: string
    napi_typeof(env, argv[1], &valuetype);
    if (valuetype == napi_string) {
        offName = GetStringProperty(env, argv[1]);
    } else {
        ACCOUNT_LOGE("Type matching failed");
    }

    // argv[2]:callback
    if (argc >= ARGS_SIZE_THREE) {
        napi_typeof(env, argv[1], &valuetype);
        if (valuetype == napi_function) {
            napi_create_reference(env, argv[1], 1, &callback);
        } else {
            ACCOUNT_LOGE("Type matching failed");
        }
    }
}
}  // namespace AccountJsKit
}  // namespace OHOS