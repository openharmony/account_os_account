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

#include "napi_os_account_common.h"
#include <string>
#include "napi_account_error.h"
#include "napi_account_common.h"
#include "napi/native_common.h"
#include "napi_os_account.h"

namespace OHOS {
namespace AccountJsKit {
NapiCreateDomainCallback::NapiCreateDomainCallback(napi_env env, napi_ref callbackRef, napi_deferred deferred)
    : env_(env), callbackRef_(callbackRef), deferred_(deferred)
{}

void NapiCreateDomainCallback::OnResult(const int32_t errCode, Parcel &parcel)
{
    std::shared_ptr<OsAccountInfo> osAccountInfo(OsAccountInfo::Unmarshalling(parcel));
    if (osAccountInfo == nullptr) {
        ACCOUNT_LOGE("failed to unmarshalling OsAccountInfo");
        return;
    }
    std::unique_lock<std::mutex> lock(lockInfo_.mutex);
    if ((callbackRef_ == nullptr) && (deferred_ == nullptr)) {
        ACCOUNT_LOGE("js callback is nullptr");
        return;
    }
    uv_loop_s *loop = nullptr;
    uv_work_t *work = nullptr;
    if (!CreateExecEnv(env_, &loop, &work)) {
        ACCOUNT_LOGE("failed to init domain plugin execution environment");
        return;
    }
    auto *asyncContext = new (std::nothrow) CreateOAForDomainAsyncContext();
    if (asyncContext == nullptr) {
        delete work;
        return;
    }
    asyncContext->osAccountInfos = *osAccountInfo;
    asyncContext->errCode = errCode;
    asyncContext->env = env_;
    asyncContext->callbackRef = callbackRef_;
    asyncContext->deferred = deferred_;
    work->data = reinterpret_cast<void *>(asyncContext);
    int resultCode = uv_queue_work_with_qos(
        loop, work, [](uv_work_t *work) {}, CreateOAForDomainCallbackCompletedWork, uv_qos_default);
    if (resultCode != 0) {
        ACCOUNT_LOGE("failed to uv_queue_work_with_qos, errCode: %{public}d", errCode);
        delete asyncContext;
        delete work;
        return;
    }
    callbackRef_ = nullptr;
    deferred_ = nullptr;
}

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
            std::string errMsg = "Parameter error. The type of \"callback\" must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
    }
    return true;
}

bool ParseCallbackAndId(napi_env env, napi_callback_info cbInfo, napi_ref &callbackRef, int &id, bool throwErr)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    if (argc == ARGS_SIZE_TWO) {
        if (!GetCallbackProperty(env, argv[argc - 1], callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            std::string errMsg = "Parameter error. The type of \"callback\" must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, throwErr);
            return false;
        }
    }
    if (!GetIntProperty(env, argv[PARAMZERO], id)) {
        ACCOUNT_LOGE("Get id failed");
        std::string errMsg = "Parameter error. The type of \"localId\" must be number";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, throwErr);
        return false;
    }
    return true;
}

bool ParseParaDeactivateOA(napi_env env, napi_callback_info cbInfo, ActivateOAAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {0};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr), false);

    if (argc < ARGS_SIZE_ONE) {
        ACCOUNT_LOGE("The number of parameters should be at least 1.");
        std::string errMsg = "The number of parameters should be at least 1";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    if (!GetIntProperty(env, argv[PARAMZERO], asyncContext->id)) {
        ACCOUNT_LOGE("Get local Id failed.");
        std::string errMsg = "The type of first arg must be number";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, true);
        return false;
    }
    return true;
}

void DeactivateOAExecuteCB(napi_env env, void *data)
{
    ActivateOAAsyncContext *asyncContext = reinterpret_cast<ActivateOAAsyncContext *>(data);
    asyncContext->errCode = OsAccountManager::DeactivateOsAccount(asyncContext->id);
}

void DeactivateOACompletedCB(napi_env env, napi_status status, void *data)
{
    ActivateOAAsyncContext *asyncContext = reinterpret_cast<ActivateOAAsyncContext *>(data);
    std::unique_ptr<ActivateOAAsyncContext> asyncContextPtr{asyncContext};
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->errCode == ERR_OK) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &dataJs));
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode);
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
}

bool ParseParaQueryOAByIdCB(napi_env env, napi_callback_info cbInfo, QueryOAByIdAsyncContext *asyncContext)
{
    return ParseCallbackAndId(env, cbInfo, asyncContext->callbackRef, asyncContext->id, asyncContext->throwErr);
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
    delete asyncContext;
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

    napi_create_string_utf8(env, info.accountId_.c_str(), info.accountId_.size(), &value);
    napi_set_named_property(env, result, "accountId", value);
    if ((info.status_ == DomainAccountStatus::LOGOUT) || (info.status_ >= DomainAccountStatus::LOG_END)) {
        napi_get_boolean(env, false, &value);
    } else {
        napi_get_boolean(env, true, &value);
    }
    napi_set_named_property(env, result, "isAuthenticated", value);
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
    napi_value idToJs = nullptr;
    napi_create_int32(env, info.GetLocalId(), &idToJs);
    napi_set_named_property(env, objOAInfo, "localId", idToJs);

    napi_value nameToJs = nullptr;
    napi_create_string_utf8(env, info.GetLocalName().c_str(), NAPI_AUTO_LENGTH, &nameToJs);
    napi_set_named_property(env, objOAInfo, "localName", nameToJs);

    napi_value shortNameToJs = nullptr;
    napi_create_string_utf8(env, info.GetShortName().c_str(), NAPI_AUTO_LENGTH, &shortNameToJs);
    napi_set_named_property(env, objOAInfo, "shortName", shortNameToJs);

    napi_value typeToJsObj = nullptr;
    napi_create_int32(env, static_cast<int>(info.GetType()), &typeToJsObj);
    napi_set_named_property(env, objOAInfo, "type", typeToJsObj);

    napi_value constraintsToJs = nullptr;
    napi_create_array(env, &constraintsToJs);
    MakeArrayToJs(env, info.GetConstraints(), constraintsToJs);
    napi_set_named_property(env, objOAInfo, "constraints", constraintsToJs);

    napi_value isVerifiedToJs = nullptr;
    napi_get_boolean(env, info.GetIsVerified(), &isVerifiedToJs);
    napi_set_named_property(env, objOAInfo, "isVerified", isVerifiedToJs);
    napi_set_named_property(env, objOAInfo, "isUnlocked", isVerifiedToJs);

    napi_value photoToJs = nullptr;
    napi_create_string_utf8(env, info.GetPhoto().c_str(), NAPI_AUTO_LENGTH, &photoToJs);
    napi_set_named_property(env, objOAInfo, "photo", photoToJs);

    napi_value createTimeToJs = nullptr;
    napi_create_int64(env, info.GetCreateTime(), &createTimeToJs);
    napi_set_named_property(env, objOAInfo, "createTime", createTimeToJs);

    napi_value lastLoginTimeToJs = nullptr;
    napi_create_int64(env, info.GetLastLoginTime(), &lastLoginTimeToJs);
    napi_set_named_property(env, objOAInfo, "lastLoginTime", lastLoginTimeToJs);

    napi_value serialNumberToJs = nullptr;
    napi_create_int64(env, info.GetSerialNumber(), &serialNumberToJs);
    napi_set_named_property(env, objOAInfo, "serialNumber", serialNumberToJs);

    napi_value isActivedToJs = nullptr;
    napi_get_boolean(env, info.GetIsActived(), &isActivedToJs);
    napi_set_named_property(env, objOAInfo, "isActived", isActivedToJs);
    napi_set_named_property(env, objOAInfo, "isActivated", isActivedToJs);

    napi_value isLoggedInToJs = nullptr;
    napi_get_boolean(env, info.GetIsLoggedIn(), &isLoggedInToJs);
    napi_set_named_property(env, objOAInfo, "isLoggedIn", isLoggedInToJs);

    napi_value isCreateCompletedToJs = nullptr;
    napi_get_boolean(env, info.GetIsCreateCompleted(), &isCreateCompletedToJs);
    napi_set_named_property(env, objOAInfo, "isCreateCompleted", isCreateCompletedToJs);

    GetOtherAccountInfoToJs(env, info, objOAInfo);
}

void GetOtherAccountInfoToJs(napi_env env, OsAccountInfo &info, napi_value &objOAInfo)
{
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
    return ParseCallbackAndId(env, cbInfo, asyncContext->callbackRef, asyncContext->id, asyncContext->throwErr);
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
    delete asyncContext;
}

bool ParseParaSetOAName(napi_env env, napi_callback_info cbInfo, SetOANameAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    if (argc == ARGS_SIZE_THREE) {
        if (!GetCallbackProperty(env, argv[argc - 1], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Get SetOAName callbackRef failed");
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
    delete asyncContext;
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
    delete asyncContext;
}

bool ParseParaActiveOA(napi_env env, napi_callback_info cbInfo, ActivateOAAsyncContext *asyncContext)
{
    return ParseCallbackAndId(env, cbInfo, asyncContext->callbackRef, asyncContext->id, asyncContext->throwErr);
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
    delete asyncContext;
}

bool ParseParaCreateOA(napi_env env, napi_callback_info cbInfo, CreateOAAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    napi_valuetype valueType = napi_undefined;
    if (argc == ARGS_SIZE_THREE) {
        napi_typeof(env, argv[ARGS_SIZE_TWO], &valueType);
        if (!GetCallbackProperty(env, argv[PARAMTWO], asyncContext->callbackRef, 1)) {
            if (!GetStringPropertyByKey(env, argv[PARAMTWO], "shortName", asyncContext->shortName)) {
                ACCOUNT_LOGE("get CreateOsAccountOptions's shortName failed");
                std::string errMsg = "Parameter error. The type of arg 3 must be function or CreateOsAccountOptions";
                AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
                return false;
            } else {
                asyncContext->hasShortName = true;
            }
        }
    }

    if (!GetStringProperty(env, argv[PARAMZERO], asyncContext->name)) {
        ACCOUNT_LOGE("Get name failed");
        std::string errMsg = "Parameter error. The type of \"localName\" must be string";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }

    int32_t type = 0;
    if (!GetIntProperty(env, argv[PARAMONE], type)) {
        ACCOUNT_LOGE("Get type failed");
        std::string errMsg = "Parameter error. The type of \"type\" must be OsAccountType";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }

    asyncContext->type = static_cast<OsAccountType>(type);
    return true;
}

static bool ParseDomainAccountInfo(napi_env env, napi_value object, DomainAccountInfo &info)
{
    if (!GetStringPropertyByKey(env, object, "domain", info.domain_)) {
        ACCOUNT_LOGE("get domainInfo's domain failed");
        return false;
    }
    if (!GetStringPropertyByKey(env, object, "accountName", info.accountName_)) {
        ACCOUNT_LOGE("get domainInfo's accountName failed");
        return false;
    }
    bool hasProp = false;
    napi_has_named_property(env, object, "accountId", &hasProp);
    if (hasProp) {
        napi_value value = nullptr;
        napi_get_named_property(env, object, "accountId", &value);
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, value, &valueType);
        if ((valueType == napi_undefined) || (valueType == napi_null)) {
            ACCOUNT_LOGI("the accountId is undefined or null");
        } else {
            if (!GetStringProperty(env, value, info.accountId_)) {
                ACCOUNT_LOGE("get domainInfo's accountId failed");
                return false;
            }
        }
    }
    if (!GetOptionalStringPropertyByKey(env, object, "serverConfigId", info.serverConfigId_)) {
        ACCOUNT_LOGE("Get domainInfo's serverConfigId failed");
        return false;
    }
    return true;
}

static bool ParseDomainOptionInfo(napi_env env, napi_value object, CreateOsAccountForDomainOptions &domainOptions)
{
    if (!GetStringPropertyByKey(env, object, "shortName", domainOptions.shortName)) {
        ACCOUNT_LOGE("Failed to get options's shortName");
        return false;
    }
    domainOptions.hasShortName = true;
    return true;
}

bool ParseParaCreateOAForDomain(napi_env env, napi_callback_info cbInfo,
    CreateOAForDomainAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);

    napi_valuetype valueType = napi_undefined;
    if (argc == ARGS_SIZE_THREE) {
        napi_typeof(env, argv[ARGS_SIZE_TWO], &valueType);
        if (!GetCallbackProperty(env, argv[PARAMTWO], asyncContext->callbackRef, 1)) {
            if (!ParseDomainOptionInfo(env, argv[PARAMTWO], asyncContext->domainOptions)) {
                ACCOUNT_LOGE("Failed to get domainOptions");
                std::string errMsg =
                    "Parameter error. The type of arg 3 must be function or CreateOsAccountForDomainOptions";
                AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
                return false;
            }
        }
    }

    int32_t id = 0;
    if (!GetIntProperty(env, argv[PARAMZERO], id)) {
        ACCOUNT_LOGE("Get type failed");
        std::string errMsg = "Parameter error. The type of \"type\" must be OsAccountType";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    asyncContext->type = static_cast<OsAccountType>(id);

    if (!ParseDomainAccountInfo(env, argv[PARAMONE], asyncContext->domainInfo)) {
        ACCOUNT_LOGE("get domainInfo failed");
        std::string errMsg = "Parameter error. The type of \"domainInfo\" must be DomainAccountInfo";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    return true;
}

void CreateOAExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGD("napi_create_async_work running");
    CreateOAAsyncContext *asyncContext = reinterpret_cast<CreateOAAsyncContext *>(data);
    if (asyncContext->hasShortName) {
        asyncContext->errCode =
            OsAccountManager::CreateOsAccount(asyncContext->name, asyncContext->shortName,
                asyncContext->type, asyncContext->osAccountInfos);
    } else {
        asyncContext->errCode =
            OsAccountManager::CreateOsAccount(asyncContext->name, asyncContext->type, asyncContext->osAccountInfos);
    }
    asyncContext->status = (asyncContext->errCode == 0) ? napi_ok : napi_generic_failure;
}

void CreateOAForDomainCompletedCB(napi_env env, napi_status status, void *data)
{
    delete reinterpret_cast<CreateOAForDomainAsyncContext *>(data);
}

void CreateOAForDomainExecuteCB(napi_env env, void *data)
{
    CreateOAForDomainAsyncContext *asyncContext = reinterpret_cast<CreateOAForDomainAsyncContext *>(data);
    auto callback = std::make_shared<NapiCreateDomainCallback>(env, asyncContext->callbackRef, asyncContext->deferred);
    asyncContext->errCode =
        OsAccountManager::CreateOsAccountForDomain(asyncContext->type, asyncContext->domainInfo,
            callback, asyncContext->domainOptions);
    if (asyncContext->errCode != ERR_OK) {
        Parcel emptyParcel;
        callback->OnResult(asyncContext->errCode, emptyParcel);
    }
    asyncContext->callbackRef = nullptr;
    asyncContext->deferred = nullptr;
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
    delete asyncContext;
}

void CreateOAForDomainCallbackCompletedWork(uv_work_t *work, int status)
{
    std::unique_ptr<uv_work_t> workPtr(work);
    napi_handle_scope scope = nullptr;
    if (!InitUvWorkCallbackEnv(work, scope)) {
        return;
    }
    std::unique_ptr<CreateOAForDomainAsyncContext> asyncContext(
        reinterpret_cast<CreateOAForDomainAsyncContext *>(work->data));
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->errCode == ERR_OK) {
        GetOACBInfoToJs(asyncContext->env, asyncContext->osAccountInfos, dataJs);
    } else {
        errJs = GenerateBusinessError(asyncContext->env, asyncContext->errCode);
    }
    ReturnCallbackOrPromise(asyncContext->env, asyncContext.get(), errJs, dataJs);
    napi_close_handle_scope(asyncContext->env, scope);
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
    if ((!asyncContext->throwErr) && (asyncContext->errCode == ERR_ACCOUNT_COMMON_PERMISSION_DENIED)) {
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
    delete asyncContext;
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
    delete asyncContext;
}

bool ParseParaGetAllCons(napi_env env, napi_callback_info cbInfo, GetAllConsAsyncContext *asyncContext)
{
    return ParseCallbackAndId(env, cbInfo, asyncContext->callbackRef, asyncContext->id, asyncContext->throwErr);
}

void GetAllConsExecuteCB(napi_env env, void *data)
{
    GetAllConsAsyncContext *asyncContext = reinterpret_cast<GetAllConsAsyncContext *>(data);
    asyncContext->errCode = OsAccountManager::GetOsAccountAllConstraints(asyncContext->id, asyncContext->constraints);
    // for compatibility
    if ((!asyncContext->throwErr) && (asyncContext->errCode == ERR_ACCOUNT_COMMON_PERMISSION_DENIED)) {
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
    delete asyncContext;
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
    delete asyncContext;
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
            std::string errMsg = "Parameter error. The type of \"callback\" must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
    }

    if (!GetIntProperty(env, argv[PARAMZERO], asyncContext->id)) {
        ACCOUNT_LOGE("Get id failed");
        std::string errMsg = "Parameter error. The type of \"localId\" must be number";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    if (!GetStringProperty(env, argv[PARAMONE], asyncContext->constraint)) {
        ACCOUNT_LOGE("Get constraint failed");
        std::string errMsg = "Parameter error. The type of \"constraint\" must be string";
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
    delete asyncContext;
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

        napi_set_named_property(env, objTypeInfo, "type", valToJs);
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
    delete asyncContext;
}

void GetForegroundOALocalIdExecuteCB(napi_env env, void *data)
{
    GetForegroundOALocalIdAsyncContext *asyncContext = reinterpret_cast<GetForegroundOALocalIdAsyncContext *>(data);
    asyncContext->errCode = OsAccountManager::GetForegroundOsAccountLocalId(asyncContext->id);
}

void GetForegroundOALocalIdCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    GetForegroundOALocalIdAsyncContext *asyncContext = reinterpret_cast<GetForegroundOALocalIdAsyncContext *>(data);
    std::unique_ptr<GetForegroundOALocalIdAsyncContext> asyncContextPtr{asyncContext};
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->errCode == ERR_OK) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &errJs));
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncContext->id, &dataJs));
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode);
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &dataJs));
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
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
    delete asyncContext;
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
    return ParseCallbackAndId(env, cbInfo, asyncContext->callbackRef, asyncContext->id, asyncContext->throwErr);
}

void GetOsAccountNameExecuteCB(napi_env env, void *data)
{
    ACCOUNT_LOGD("Running napi_create_async_work");
    GetOsAccountNameContext *asyncContext = reinterpret_cast<GetOsAccountNameContext *>(data);
    asyncContext->errCode = OsAccountManager::GetOsAccountName(asyncContext->name);
}

void GetOsAccountNameCallbackCompletedCB(napi_env env, napi_status status, void *data)
{
    ACCOUNT_LOGD("Complete napi_create_async_work");
    GetOsAccountNameContext *asyncContext = reinterpret_cast<GetOsAccountNameContext *>(data);
    napi_value errJs = nullptr;
    napi_value dataJs = nullptr;
    if (asyncContext->errCode == napi_ok) {
        napi_get_null(env, &errJs);
        napi_create_string_utf8(env, asyncContext->name.c_str(), NAPI_AUTO_LENGTH, &dataJs);
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode);
        napi_get_null(env, &dataJs);
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
    delete asyncContext;
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
    delete asyncContext;
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
    if ((!asyncContext->throwErr) && (asyncContext->errCode == ERR_ACCOUNT_COMMON_PERMISSION_DENIED)) {
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
    delete asyncContext;
}

bool ParseParaGetIdByUid(napi_env env, napi_callback_info cbInfo, GetIdByUidAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc == ARGS_SIZE_TWO) {
        if (!GetCallbackProperty(env, argv[argc - 1], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            std::string errMsg = "Parameter error. The type of \"callback\" must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
    }

    if (!GetIntProperty(env, argv[PARAMZERO], asyncContext->uid)) {
        ACCOUNT_LOGE("Get uid failed");
        std::string errMsg = "Parameter error. The type of \"uid\" must be number";
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

    if (!ParseDomainAccountInfo(env, argv[PARAMZERO], asyncContext->domainInfo)) {
        ACCOUNT_LOGE("get domainInfo failed");
        std::string errMsg = "DomainInfo parse failed";
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
    delete asyncContext;
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
    delete asyncContext;
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
    delete asyncContext;
}

bool ParseParaSetPhoto(napi_env env, napi_callback_info cbInfo, SetOAPhotoAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc == ARGS_SIZE_THREE) {
        if (!GetCallbackProperty(env, argv[argc - 1], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            std::string errMsg = "Parameter error. The type of \"callback\" must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
    }

    if (!GetIntProperty(env, argv[PARAMZERO], asyncContext->id)) {
        ACCOUNT_LOGE("Get id failed");
        std::string errMsg = "Parameter error. The type of \"localId\" must be number";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    if (!GetStringProperty(env, argv[PARAMONE], asyncContext->photo)) {
        ACCOUNT_LOGE("Get photo failed");
        std::string errMsg = "Parameter error. The type of \"photo\" must be string";
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
    delete asyncContext;
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
        napi_create_uint32(env, asyncContext->maxOsAccountNumber, &dataJs);
    } else {
        errJs = GenerateBusinessError(env, asyncContext->errCode, asyncContext->throwErr);
        napi_get_null(env, &dataJs);
    }
    ProcessCallbackOrPromise(env, asyncContext, errJs, dataJs);
    delete asyncContext;
}

bool ParseParaIsActived(napi_env env, napi_callback_info cbInfo, IsActivedAsyncContext *asyncContext)
{
    return ParseCallbackAndId(env, cbInfo, asyncContext->callbackRef, asyncContext->id, asyncContext->throwErr);
}

void IsActivedExecuteCB(napi_env env, void *data)
{
    IsActivedAsyncContext *asyncContext = reinterpret_cast<IsActivedAsyncContext *>(data);
    asyncContext->errCode = OsAccountManager::IsOsAccountActived(asyncContext->id, asyncContext->isOsAccountActived);
    // for compatibility
    if ((!asyncContext->throwErr) && (asyncContext->errCode == ERR_ACCOUNT_COMMON_PERMISSION_DENIED)) {
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
    delete asyncContext;
}

bool ParseParaIsEnable(napi_env env, napi_callback_info cbInfo, IsConEnableAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc == ARGS_SIZE_ONE) {
        std::vector<int> ids;
        ErrCode errCode = OsAccountManager::QueryActiveOsAccountIds(ids);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("Get id failed");
            AccountNapiThrow(env, errCode, asyncContext->throwErr);
            return false;
        }
        if (ids.empty()) {
            ACCOUNT_LOGE("No Active OsAccount Ids");
            AccountNapiThrow(env, ERR_ACCOUNT_COMMON_INVALID_PARAMETER, asyncContext->throwErr);
            return false;
        }
        asyncContext->id = ids[0];
        if (!GetStringProperty(env, argv[PARAMZERO], asyncContext->constraint)) {
            ACCOUNT_LOGE("Get constraint failed");
            std::string errMsg = "Parameter error. The type of \"constraint\" must be string";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
        return true;
    }
    if (argc == ARGS_SIZE_THREE) {
        if (!GetCallbackProperty(env, argv[argc - 1], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            std::string errMsg = "Parameter error. The type of \"callback\" must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
    }

    if (!GetIntProperty(env, argv[PARAMZERO], asyncContext->id)) {
        ACCOUNT_LOGE("Get id failed");
        std::string errMsg = "Parameter error. The type of \"localId\" must be number";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    if (!GetStringProperty(env, argv[PARAMONE], asyncContext->constraint)) {
        ACCOUNT_LOGE("Get constraint failed");
        std::string errMsg = "Parameter error. The type of \"constraint\" must be string";
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
    if ((!asyncContext->throwErr) && (asyncContext->errCode == ERR_ACCOUNT_COMMON_PERMISSION_DENIED)) {
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
    delete asyncContext;
}

bool ParseParaGetType(napi_env env, napi_callback_info cbInfo, GetTypeAsyncContext *asyncContext)
{
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc == ARGS_SIZE_ZERO) {
        return true;
    }

    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[PARAMZERO], &valueType);
    if (valueType == napi_number) {
        napi_get_value_int32(env, argv[PARAMZERO], &(asyncContext->id));
        asyncContext->withId = true;
    } else if (valueType == napi_function) {
        napi_create_reference(env, argv[PARAMZERO], 1, &(asyncContext->callbackRef));
    } else {
        ACCOUNT_LOGE("Get callbackRef or id failed.");
        std::string errMsg = "Parameter error. The type of arg " + std::to_string(argc) + " must be function or number";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    return true;
}

void GetTypeExecuteCB(napi_env env, void *data)
{
    GetTypeAsyncContext *asyncContext = reinterpret_cast<GetTypeAsyncContext *>(data);
    if (asyncContext->withId) {
        asyncContext->errCode = OsAccountManager::GetOsAccountType(asyncContext->id, asyncContext->type);
    } else {
        asyncContext->errCode = OsAccountManager::GetOsAccountTypeFromProcess(asyncContext->type);
    }
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
    delete asyncContext;
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
    delete asyncContext;
}

static bool ParseParaIsVerifiedWithOneParam(
    napi_env env, napi_value value, IsVerifiedAsyncContext *asyncContext)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, value, &valueType);
    if (valueType == napi_number) {
        if (!GetIntProperty(env, value, asyncContext->id)) {
            ACCOUNT_LOGE("Get id failed");
            std::string errMsg = "Parameter error. The type of \"localId\" must be number";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
    } else if (valueType == napi_function) {
        if (!GetCallbackProperty(env, value, asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            std::string errMsg = "The type of arg 1 must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
    } else if ((valueType == napi_undefined) || (valueType == napi_null)) {
        ACCOUNT_LOGI("id is undefined or null");
    } else {
        ACCOUNT_LOGE("Wrong arg type, expected number or function");
        std::string errMsg = "The type of arg 1 must be number or function";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    return true;
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
        return ParseParaIsVerifiedWithOneParam(env, argv[PARAMZERO], asyncContext);
    }
    if (argc == ARGS_SIZE_TWO) {
        if (!GetCallbackProperty(env, argv[argc - 1], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            std::string errMsg = "Parameter error. The type of \"callback\" must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[PARAMZERO], &valueType);
        if ((valueType == napi_undefined) || (valueType == napi_null)) {
            ACCOUNT_LOGI("id is undefined or null");
        } else {
            if (!GetIntProperty(env, argv[PARAMZERO], asyncContext->id)) {
                ACCOUNT_LOGE("Get id failed");
                std::string errMsg = "Parameter error. The type of \"localId\" must be number";
                AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
                return false;
            }
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
    if ((!asyncContext->throwErr) && (asyncContext->errCode == ERR_ACCOUNT_COMMON_PERMISSION_DENIED)) {
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
    delete asyncContext;
}

bool ParseParaSerialNumId(napi_env env, napi_callback_info cbInfo, GetSerialNumIdCBInfo *asyncContext)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {0};
    napi_get_cb_info(env, cbInfo, &argc, argv, nullptr, nullptr);
    if (argc == ARGS_SIZE_TWO) {
        if (!GetCallbackProperty(env, argv[argc - 1], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            std::string errMsg = "Parameter error. The type of \"callback\" must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
    }
    if (!GetLongIntProperty(env, argv[PARAMZERO], asyncContext->serialNumber)) {
        ACCOUNT_LOGE("Get serialNumber failed");
        std::string errMsg = "Parameter error. The type of \"serialNumber\" must be number";
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
    delete asyncContext;
}

bool ParseParaGetSerialNum(napi_env env, napi_callback_info cbInfo, GetSerialNumForOAInfo *asyncContext)
{
    return ParseCallbackAndId(env, cbInfo, asyncContext->callbackRef, asyncContext->id, asyncContext->throwErr);
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
    delete asyncContext;
}

bool ParseParaIsTestOA(napi_env env, napi_callback_info cbInfo, IsTestOAInfo *asyncContext)
{
    return ParseOneParaContext(env, cbInfo, asyncContext);
}

bool ParseParaIsMainOA(napi_env env, napi_callback_info cbInfo, IsMainOAInfo *asyncContext)
{
    return ParseOneParaContext(env, cbInfo, asyncContext);
}

static bool ParseParamForActiveSubscriber(const napi_env &env, const std::string &type, SubscribeCBInfo *asyncContext,
                                          size_t argc, napi_value *argv)
{
    if (argc < ARGS_SIZE_THREE) {
        ACCOUNT_LOGE("The arg number less than 3 characters");
        std::string errMsg = "Parameter error. The number of parameters should be at least 3";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    if (argc >= ARGS_SIZE_THREE) {
        if (!GetCallbackProperty(env, argv[PARAMTWO], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            std::string errMsg = "Parameter error. The type of \"callback\" must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
    }

    // argv[0] type: 'activate' | 'activating'
    if (type == "activate") {
        asyncContext->osSubscribeType = OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVED;
    } else {
        asyncContext->osSubscribeType = OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATING;
    }

    // argv[1] name: string
    if (!GetStringProperty(env, argv[PARAMONE], asyncContext->name)) {
        ACCOUNT_LOGE("Get name failed");
        std::string errMsg = "Parameter error. The type of \"name\" must be string";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    size_t nameSize = asyncContext->name.size();
    if (nameSize == 0 || nameSize > MAX_SUBSCRIBER_NAME_LEN) {
        ACCOUNT_LOGE("Subscriber name size %{public}zu is invalid.", nameSize);
        std::string errMsg = "Parameter error. The length of \"name\" is invalid";
        AccountNapiThrow(env, ERR_JS_INVALID_PARAMETER, errMsg, asyncContext->throwErr);
        return false;
    }

    return true;
}

static bool ParseParamForSwitchSubscriber(const napi_env &env, const std::string &type, SubscribeCBInfo *asyncContext,
                                          size_t argc, napi_value *argv)
{
    if (argc < ARGS_SIZE_TWO) {
        ACCOUNT_LOGE("The number of parameters should be at least 2");
        std::string errMsg = "Parameter error. The number of parameters should be at least 2";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    if (argc >= ARGS_SIZE_TWO) {
        if (!GetCallbackProperty(env, argv[PARAMONE], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed");
            std::string errMsg = "Parameter error. The type of \"callback\" must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
    }
    // argv[0] type: 'switched' | 'switching'
    if (type == "switched") {
        asyncContext->osSubscribeType = OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHED;
    } else {
        asyncContext->osSubscribeType = OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHING;
    }

    return true;
}

bool ParseParaToSubscriber(const napi_env &env, napi_callback_info cbInfo, SubscribeCBInfo *asyncContext,
                           napi_value *thisVar)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, cbInfo, &argc, argv, thisVar, NULL), false);
    if (argc < ARGS_SIZE_TWO) {
        ACCOUNT_LOGE("The number of parameters should be at least 2");
        std::string errMsg = "Parameter error. The number of parameters should be at least 2";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    std::string type;
    if (!GetStringProperty(env, argv[PARAMZERO], type)) {
        ACCOUNT_LOGE("Get type failed.");
        std::string errMsg = "Parameter error. The type of \"type\" must be string";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    if ((type == "activate" || type == "activating")) {
        return ParseParamForActiveSubscriber(env, type, asyncContext, argc, argv);
    }
    if (type == "switched" || type == "switching") {
        return ParseParamForSwitchSubscriber(env, type, asyncContext, argc, argv);
    }
    ACCOUNT_LOGE("Get type fail, %{public}s is invalid.", type.c_str());
    std::string errMsg = "Parameter error. The content of \"type\" must be \"activate|activating|switched|switching\"";
    AccountNapiThrow(env, ERR_JS_INVALID_PARAMETER, errMsg, asyncContext->throwErr);
    return false;
}

static bool ParseParamForActiveUnsubscriber(const napi_env &env, const std::string &type,
                                            UnsubscribeCBInfo *asyncContext, size_t argc, napi_value *argv)
{
    if (argc < ARGS_SIZE_TWO) {
        ACCOUNT_LOGE("The arg number less than 2 characters.");
        std::string errMsg = "The arg number must be at least 2 characters";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    if (argc >= ARGS_SIZE_THREE) {
        if (!GetCallbackProperty(env, argv[PARAMTWO], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed.");
            std::string errMsg = "The type of arg " + std::to_string(PARAMTWO + 1) + " must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
    }

    // argv[0] type: 'activate' | 'activating'
    if (type == "activate") {
        asyncContext->osSubscribeType = OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVED;
    } else {
        asyncContext->osSubscribeType = OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATING;
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

static bool ParseParamForSwitchUnsubscriber(const napi_env &env, const std::string &type,
                                            UnsubscribeCBInfo *asyncContext, size_t argc, napi_value *argv)
{
    if (argc < ARGS_SIZE_ONE) {
        ACCOUNT_LOGE("The arg number less than 1 characters.");
        std::string errMsg = "The arg number must be at least 1 characters";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    if (argc >= ARGS_SIZE_TWO) {
        if (!GetCallbackProperty(env, argv[PARAMONE], asyncContext->callbackRef, 1)) {
            ACCOUNT_LOGE("Get callbackRef failed.");
            std::string errMsg = "The type of arg " + std::to_string(PARAMONE + 1) + " must be function";
            AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
            return false;
        }
    }
    // argv[0] type: 'switched' | 'switching'
    if (type == "switched") {
        asyncContext->osSubscribeType = OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHED;
    } else {
        asyncContext->osSubscribeType = OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHING;
    }

    return true;
}

bool ParseParaToUnsubscriber(const napi_env &env, napi_callback_info cbInfo, UnsubscribeCBInfo *asyncContext,
                             napi_value *thisVar)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, cbInfo, &argc, argv, thisVar, NULL), false);
    if (argc < ARGS_SIZE_ONE) {
        ACCOUNT_LOGE("The arg number less than 1 characters.");
        std::string errMsg = "Parameter error. The number of parameters should be at least 1";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    std::string type;
    if (!GetStringProperty(env, argv[PARAMZERO], type)) {
        ACCOUNT_LOGE("Get type failed.");
        std::string errMsg = "Parameter error. The type of \"type\" must be string";
        AccountNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg, asyncContext->throwErr);
        return false;
    }
    if ((type == "activate" || type == "activating")) {
        return ParseParamForActiveUnsubscriber(env, type, asyncContext, argc, argv);
    }
    if (type == "switched" || type == "switching") {
        return ParseParamForSwitchUnsubscriber(env, type, asyncContext, argc, argv);
    }
    ACCOUNT_LOGE("Get type fail, %{public}s is invalid.", type.c_str());
    std::string errMsg = "Parameter error. The content of \"type\" must be \"activate|activating|switched|switching\"";
    AccountNapiThrow(env, ERR_JS_INVALID_PARAMETER, errMsg, asyncContext->throwErr);
    return false;
}
}  // namespace AccountJsKit
}  // namespace OHOS
