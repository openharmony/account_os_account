/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "appaccount_impl.h"

#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "app_account_manager.h"
#include "cj_lambda.h"
#include "securec.h"
#include "appaccount_common.h"
#include "appaccount_error.h"
#include "appaccount_defination.h"
#include "appaccount_parameter_parse.h"

namespace OHOS::AccountSA {
int32_t CJAppAccountImpl::createAccount(std::string name, CCreateAccountOptions cOptions)
{
    CreateAccountOptions options{};
    Convert2CreateAccountOptions(cOptions, options);
    int32_t ret = ConvertToJSErrCode(AppAccountManager::CreateAccount(name, options));
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("create account failed");
        return ret;
    }
    return ret;
}

int32_t CJAppAccountImpl::removeAccount(std::string name)
{
    int32_t ret = ConvertToJSErrCode(AppAccountManager::DeleteAccount(name));
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("remove account failed");
        return ret;
    }
    return ret;
}

int32_t CJAppAccountImpl::setAppAccess(std::string name, std::string bundleNmae, bool isAccessible)
{
    int32_t ret = ConvertToJSErrCode(AppAccountManager::SetAppAccess(name, bundleNmae, isAccessible));
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("setAppAccess failed");
        return ret;
    }
    return ret;
}

RetDataBool CJAppAccountImpl::checkAppAccess(std::string name, std::string bundleNmae)
{
    RetDataBool ret = { .code = ERR_CJ_INVALID_INSTANCE_CODE, .data = 0 };
    bool isAccessible;
    int32_t err = ConvertToJSErrCode(AppAccountManager::CheckAppAccess(name, bundleNmae, isAccessible));
    if (err != ERR_OK) {
        ACCOUNT_LOGE("checkAppAccess failed");
        ret.code = err;
        ret.data = false;
        return ret;
    }
    ret.code = err;
    ret.data = isAccessible;
    return ret;
}

RetDataBool CJAppAccountImpl::checkDataSyncEnabled(std::string name)
{
    RetDataBool ret = { .code = ERR_CJ_INVALID_INSTANCE_CODE, .data = 0 };
    bool result;
    int32_t err = ConvertToJSErrCode(AppAccountManager::CheckAppAccountSyncEnable(name, result));
    if (err != ERR_OK) {
        ACCOUNT_LOGE("checkDataSyncEnabled failed");
        ret.code = err;
        ret.data = false;
        return ret;
    }
    ret.code = err;
    ret.data = result;
    return ret;
}

int32_t CJAppAccountImpl::setCredential(std::string name, std::string credentialType, std::string credential)
{
    int32_t ret = ConvertToJSErrCode(AppAccountManager::SetAccountCredential(name, credentialType, credential));
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("setCredential failed");
        return ret;
    }
    return ret;
}

int32_t CJAppAccountImpl::setDataSyncEnabled(std::string name, bool isEnabled)
{
    int32_t ret = ConvertToJSErrCode(AppAccountManager::SetAppAccountSyncEnable(name, isEnabled));
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("setDataSyncEnabled failed");
        return ret;
    }
    return ret;
}

int32_t CJAppAccountImpl::setCustomData(std::string name, std::string key, std::string value)
{
    int32_t ret = ConvertToJSErrCode(AppAccountManager::SetAssociatedData(name, key, value));
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("setCustomData failed");
        return ret;
    }
    return ret;
}

ErrCArrAppAccountInfo CJAppAccountImpl::getAccountsByOwner(std::string owner)
{
    ErrCArrAppAccountInfo res{};
    std::vector<AppAccountInfo> appAccounts;
    int32_t err = ConvertToJSErrCode(AppAccountManager::QueryAllAccessibleAccounts(owner, appAccounts));
    if (err != ERR_OK) {
        ACCOUNT_LOGE("getAccountsByOwner failed");
        res.err = err;
        return res;
    }
    res.err = err;
    res.cArrAppAccountInfo = Convert2CArrAppAccountInfo(appAccounts);
    return res;
}

RetDataCString CJAppAccountImpl::getCredential(std::string name, std::string credentialType)
{
    RetDataCString ret = { .code = ERR_CJ_SUCCESS, .data = nullptr };
    std::string credential;
    int32_t err = ConvertToJSErrCode(AppAccountManager::GetAccountCredential(name, credentialType, credential));
    if (err != ERR_OK) {
        ACCOUNT_LOGE("getCredential failed");
        ret.code = err;
        ret.data = nullptr;
        return ret;
    }
    ret.code = err;
    ret.data = MallocCString(credential);
    return ret;
}

RetDataCString CJAppAccountImpl::getCustomData(std::string name, std::string key)
{
    RetDataCString ret = { .code = ERR_CJ_SUCCESS, .data = nullptr };
    std::string value;
    int32_t err = ConvertToJSErrCode(AppAccountManager::GetAssociatedData(name, key, value));
    if (err != ERR_OK) {
        ACCOUNT_LOGE("getCustomDataSync failed");
        ret.code = err;
        ret.data = nullptr;
        return ret;
    }
    ret.code = err;
    ret.data = MallocCString(value);
    return ret;
}

RetDataCString CJAppAccountImpl::getAuthToken(std::string name, std::string owner, std::string authType)
{
    RetDataCString ret = { .code = ERR_CJ_SUCCESS, .data = nullptr };
    std::string token;
    int32_t err = ConvertToJSErrCode(AppAccountManager::GetAuthToken(name, owner, authType, token));
    if (err != ERR_OK) {
        ACCOUNT_LOGE("getAuthToken failed");
        ret.code = err;
        ret.data = nullptr;
        return ret;
    }
    ret.code = err;
    ret.data = MallocCString(token);
    return ret;
}

int32_t CJAppAccountImpl::setAuthToken(std::string name, std::string authType, std::string token)
{
    int32_t err = ConvertToJSErrCode(AppAccountManager::SetOAuthToken(name, authType, token));
    if (err != ERR_OK) {
        ACCOUNT_LOGE("setAuthToken failed");
        return err;
    }
    return err;
}

int32_t CJAppAccountImpl::deleteAuthToken(
    std::string name, std::string owner, std::string authType, std::string token)
{
    int32_t err = ConvertToJSErrCode(AppAccountManager::DeleteAuthToken(name, owner, authType, token));
    if (err != ERR_OK) {
        ACCOUNT_LOGE("deleteAuthToken failed");
        return err;
    }
    return err;
}

int32_t CJAppAccountImpl::setAuthTokenVisibility(
    std::string name, std::string authType, std::string bundleName, bool isVisible)
{
    int32_t err = ConvertToJSErrCode(AppAccountManager::SetAuthTokenVisibility(name, authType, bundleName, isVisible));
    if (err != ERR_OK) {
        ACCOUNT_LOGE("setAuthTokenVisibility failed");
        return err;
    }
    return err;
}

RetDataBool CJAppAccountImpl::checkAuthTokenVisibility(std::string name, std::string authType, std::string bundleName)
{
    RetDataBool ret = { .code = ERR_CJ_INVALID_INSTANCE_CODE, .data = 0 };
    bool isVisible;
    int32_t err = ConvertToJSErrCode(
        AppAccountManager::CheckAuthTokenVisibility(name, authType, bundleName, isVisible));
    if (err != ERR_OK) {
        ACCOUNT_LOGE("checkAuthTokenVisibility failed");
        ret.code = err;
        ret.data = false;
        return ret;
    }
    ret.code = err;
    ret.data = isVisible;
    return ret;
}

ErrCArrAuthTokenInfo CJAppAccountImpl::getAllAuthTokens(std::string name, std::string owner)
{
    ErrCArrAuthTokenInfo res{};
    std::vector<OAuthTokenInfo> tokenInfos;
    int32_t err = ConvertToJSErrCode(AppAccountManager::GetAllOAuthTokens(name, owner, tokenInfos));
    if (err != ERR_OK) {
        ACCOUNT_LOGE("getAllAuthTokens failed");
        res.err = err;
        return res;
    }
    res.err = err;
    res.cArrAuthTokenInfo = Convert2CArrAuthTokenInfo(tokenInfos);
    return res;
}

RetDataCArrString CJAppAccountImpl::getAuthList(std::string name, std::string authType)
{
    RetDataCArrString res = { .code = ERR_CJ_INVALID_INSTANCE_CODE, .data = {.head = nullptr, .size = 0}};
    std::set<std::string> authList;
    int32_t err = ConvertToJSErrCode(AppAccountManager::GetAuthList(name, authType, authList));
    if (err != ERR_OK) {
        ACCOUNT_LOGE("getAuthList failed");
        res.code = err;
        return res;
    }
    res.code = err;
    res.data = ConvertSet2CArrString(authList);
    return res;
}

ErrCAuthenticatorInfo CJAppAccountImpl::queryAuthenticatorInfo(std::string owner)
{
    ErrCAuthenticatorInfo res{};
    AuthenticatorInfo info;
    int32_t err = ConvertToJSErrCode(AppAccountManager::GetAuthenticatorInfo(owner, info));
    if (err != ERR_OK) {
        ACCOUNT_LOGE("queryAuthenticatorInfo failed");
        return {err, {}};
    }
    res.err = err;
    res.cAuthenticatorInfo = Convert2CAuthenticatorInfo(info);
    return res;
}

int32_t CJAppAccountImpl::deleteCredential(std::string name, std::string credentialType)
{
    int32_t err = ConvertToJSErrCode(AppAccountManager::DeleteAccountCredential(name, credentialType));
    if (err != ERR_OK) {
        ACCOUNT_LOGE("deleteCredential failed");
        return err;
    }
    return err;
}

ErrCArrAppAccountInfo CJAppAccountImpl::getAllAccounts()
{
    ErrCArrAppAccountInfo res{};
    std::vector<AppAccountInfo> appAccounts;
    int32_t err = ConvertToJSErrCode(AppAccountManager::GetAllAccessibleAccounts(appAccounts));
    if (err != ERR_OK) {
        ACCOUNT_LOGE("getAllAccounts failed");
        res.err = err;
        return res;
    }
    res.err = err;
    res.cArrAppAccountInfo = Convert2CArrAppAccountInfo(appAccounts);
    return res;
}

bool CJAppAccountImpl::IsSameFunction(
    const std::function<void(CArrAppAccountInfo)> *f1, const std::function<void(CArrAppAccountInfo)> *f2)
{
    if (f1 == nullptr || f2 == nullptr) {
        return false;
    }
    return f1 == f2;
}

bool CJAppAccountImpl::IsExitSubscibe(AsyncContextForSubscribe *context)
{
    for (size_t idx = 0; idx < g_appAccountSubscribes.size(); ++idx) {
        if (IsSameFunction(&context->callbackRef, &g_appAccountSubscribes[idx]->callbackRef)) {
            return true;
        }
    }
    return false;
}

int32_t CJAppAccountImpl::on(
    std::string type, CArrString owners, void (*callback)(CArrAppAccountInfo cArrAppAccountInfo))
{
    std::vector<std::string> ownersVec = Convert2VecString(owners);
    auto context = std::make_unique<AsyncContextForSubscribe>();
    context->type = type;
    context->owners = ownersVec;
    context->callbackRef = CJLambda::Create(callback);
    AppAccountSubscribeInfo subscribeInfo(context->owners);
    context->subscriber = std::make_shared<SubscribePtr>(subscribeInfo);
    if (context->subscriber == nullptr) {
        return ERR_CJ_INVALID_INSTANCE_CODE;
    }
    context->subscriber->SetCallbackRef(context->callbackRef);
    std::lock_guard<std::mutex> lock(mutex_);
    if (IsExitSubscibe(context.get())) {
        return ERR_CJ_INVALID_INSTANCE_CODE;
    }
    int32_t ret = ConvertToJSErrCode(AppAccountManager::SubscribeAppAccount(context->subscriber));
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("accountChange subscribe failed");
        return ret;
    }
    g_appAccountSubscribes.emplace_back(context.get());
    context.release();
    return ret;
}

void CJAppAccountImpl::GetSubscriberByUnsubscribe(std::vector<std::shared_ptr<SubscribePtr>> &subscribers)
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto item : g_appAccountSubscribes) {
        subscribers.emplace_back(item->subscriber);
    }
}

int32_t CJAppAccountImpl::off(std::string type, void (*callback)(CArrAppAccountInfo cArrAppAccountInfo))
{
    int32_t ret;
    bool hasFailed = false;
    int32_t E_ERROR = 0;
    AsyncContextForUnSubscribe *context = new (std::nothrow) AsyncContextForUnSubscribe();
    context->type = type;
    context->callbackRef = CJLambda::Create(callback);
    std::vector<std::shared_ptr<SubscribePtr>> subscribers = {nullptr};
    GetSubscriberByUnsubscribe(subscribers);
    context->subscribers = subscribers;
    if (callback == nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto offSubscriber : context->subscribers) {
            ret = ConvertToJSErrCode(AppAccountManager::UnsubscribeAppAccount(offSubscriber));
            if (ret != ERR_OK) {
                hasFailed = true;
                E_ERROR = ret;
            }
        }
        g_appAccountSubscribes.clear();
    } else {
        std::lock_guard<std::mutex> lock(mutex_);
        for (size_t idx = 0; idx < context->subscribers.size(); ++idx) {
            if (!IsSameFunction(&context->callbackRef, &context->subscribers[idx]->ref_)) {
                continue;
            }
            ret = ConvertToJSErrCode(
                AppAccountManager::UnsubscribeAppAccount(context->subscribers[idx]));
            if (ret != ERR_OK) {
                hasFailed = true;
                E_ERROR = ret;
            }
            g_appAccountSubscribes.erase(g_appAccountSubscribes.begin() + idx);
            break;
        }
    }
    return hasFailed ? E_ERROR : ERR_OK;
}

bool CJAppAccountImpl::ParseContextForCheckAccountLabels(std::string name, std::string owner, CArrString labels,
    const std::function<void(RetDataBool)> &callbackRef, std::unique_ptr<CheckAccountLabelsContext> &context)
{
    context->name = name;
    context->owner = owner;
    if (labels.size == 0) {
        return false;
    }
    context->labels = Convert2VecString(labels);
    context->callbackRef = callbackRef;
    return true;
}

int32_t CJAppAccountImpl::checkAccountLabels(std::string name, std::string owner, CArrString labels,
    const std::function<void(RetDataBool)> &callbackRef)
{
    RetDataBool ret = { .code = ERR_CJ_INVALID_INSTANCE_CODE, .data = 0 };
    auto context = std::make_unique<CheckAccountLabelsContext>();
    if (!ParseContextForCheckAccountLabels(name, owner, labels, callbackRef, context)) {
        ret.code = ERR_CJ_PARAMETER_ERROR;
        callbackRef(ret);
        return ret.code;
    }
    sptr<AuthenticatorAsyncCallback> callback = new (std::nothrow) AuthenticatorAsyncCallback(
        context->callbackRef, nullptr);
    if (callback == nullptr) {
        context->errCode = ERR_CJ_INVALID_INSTANCE_CODE;
        callbackRef(ret);
        return ERR_CJ_INVALID_INSTANCE_CODE;
    }
    int err =  ConvertToJSErrCode(
        AppAccountManager::CheckAccountLabels(name, owner, Convert2VecString(labels), callback));
    if (callback->errCode == ERR_OK) {
        ret.data = callback->onResultRetBool;
    } else {
        ret.code = callback->errCode;
    }
    if (err != ERR_OK) {
        ACCOUNT_LOGE("CheckAccountLabels failed");
        callbackRef(ret);
        return err;
    }
    callbackRef(ret);
    return err;
}

bool CJAppAccountImpl::ParseContextForSelectAccount(CSelectAccountsOptions cOptions,
    const std::function<void(ErrCArrAppAccountInfo)> &callbackRef,
    std::unique_ptr<SelectAccountsContext> &context)
{
    SelectAccountsOptions options{};
    Convert2SelectAccountsOptions(cOptions, options);
    if (options.allowedAccounts.size() != 0) {
        options.hasAccounts = true;
    } else {
        options.hasAccounts = false;
    }
    if (options.allowedOwners.size() != 0) {
        options.hasOwners = true;
    } else {
        options.hasOwners = false;
    }
    if (options.requiredLabels.size() != 0) {
        options.hasLabels = true;
    } else {
        options.hasLabels = false;
    }
    context->options = options;
    context->callbackRef = callbackRef;
    return true;
}

int32_t CJAppAccountImpl::selectAccountByOptions(
    CSelectAccountsOptions cOptions, const std::function<void(ErrCArrAppAccountInfo)> &callbackRef)
{
    ErrCArrAppAccountInfo ret = {.err = ERR_CJ_INVALID_INSTANCE_CODE, .cArrAppAccountInfo = {
        .head = nullptr, .size = 0}};
    auto context = std::make_unique<SelectAccountsContext>();
    if (!ParseContextForSelectAccount(cOptions, callbackRef, context)) {
        ret.err = ERR_CJ_PARAMETER_ERROR;
        callbackRef(ret);
        return ret.err;
    }
    sptr<AuthenticatorAsyncCallback> callback = new (std::nothrow) AuthenticatorAsyncCallback(nullptr,
        context->callbackRef);
    if (callback == nullptr) {
        context->errCode = ERR_CJ_INVALID_INSTANCE_CODE;
        callbackRef(ret);
        return ERR_CJ_INVALID_INSTANCE_CODE;
    }
    int err = ConvertToJSErrCode(
        AppAccountManager::SelectAccountsByOptions(context->options, callback));
    std::vector<std::string> names = callback->onResultRetNames;
    std::vector<std::string> owners = callback->onResultRetOwners;
    if (names.size() != owners.size()) {
        callback->errCode = ERR_CJ_ACCOUNT_AUTHENTICATOR_SERVICE_EXCEPTION;
    }
    if (callback->errCode == ERR_OK) {
        ret.cArrAppAccountInfo = Convert2CArrAppAccountInfo(names, owners);
    } else {
        ret.err = callback->errCode;
    }
    if (err != ERR_OK) {
        ACCOUNT_LOGE("selectAccountByOptions failed");
        callbackRef(ret);
        return err;
    }
    callbackRef(ret);
    return err;
}

void CJAppAccountImpl::ParseContextForVerifyCredential(
    CAuthCallback callbackId,
    CVerifyCredentialOptions cOptions,
    JSAuthCallback &callback,
    VerifyCredentialOptions &options)
{
    options.credential = cOptions.credential;
    options.credentialType = cOptions.credentialType;
    if (cOptions.parameters.size != 0) {
        SetDataParameters(cOptions.parameters, options.parameters);
    }
    if (callbackId.onRequestContinued != nullptr) {
        callback.onRequestContinued = CJLambda::Create(callbackId.onRequestContinued);
    }
    callback.onResult = CJLambda::Create(callbackId.onResult);
    callback.onRequestRedirected = CJLambda::Create(callbackId.onRequestRedirected);
}

int32_t CJAppAccountImpl::verifyCredential(
    std::string name, std::string owner, CAuthCallback callbackId, CVerifyCredentialOptions cOptions)
{
    VerifyCredentialOptions options;
    JSAuthCallback callback;
    ParseContextForVerifyCredential(callbackId, cOptions, callback, options);
    sptr<AppAccountManagerCallback> appAccountMgrCb = new (std::nothrow) AppAccountManagerCallback(callback);
    if (appAccountMgrCb == nullptr) {
        ACCOUNT_LOGE("Failed to create AppAccountManagerCallback for insufficient memory");
        AAFwk::Want result;
        std::string value = std::string();
        appAccountMgrCb->OnResult(ERR_CJ_SYSTEM_SERVICE_EXCEPTION, result);
        callback.onResult(ERR_CJ_SYSTEM_SERVICE_EXCEPTION, Convert2CAuthResult(value, value, value, value));
        return ERR_CJ_SYSTEM_SERVICE_EXCEPTION;
    }
    int32_t errCode = ConvertToJSErrCode(
        AppAccountManager::VerifyCredential(name, owner, options, appAccountMgrCb));
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("verifyCredential failed");
        AAFwk::Want result;
        std::string value = std::string();
        appAccountMgrCb->OnResult(ERR_CJ_SYSTEM_SERVICE_EXCEPTION, result);
        callback.onResult(ERR_CJ_SYSTEM_SERVICE_EXCEPTION, Convert2CAuthResult(value, value, value, value));
        return errCode;
    }
    // account: AppAccountInfo
    std::string nameResult = appAccountMgrCb->nameResult;
    std::string ownerResult = appAccountMgrCb->ownerResult;
    //tokenInfo: AuthTokenInfo
    std::string authTypeResult = appAccountMgrCb->authTypeResult;
    std::string tokenResult = appAccountMgrCb->tokenResult;
    CAuthResult result = Convert2CAuthResult(nameResult, ownerResult, authTypeResult, tokenResult);
    callback.onResult(errCode, result);
    return errCode;
}

void CJAppAccountImpl::ParseContextForSetAuthenticatorProperties(
    CAuthCallback callbackId, CSetPropertiesOptions cOptions, JSAuthCallback &callback, SetPropertiesOptions &options)
{
    if (cOptions.properties.size != 0) {
        SetDataParameters(cOptions.properties, options.properties);
    }
    if (cOptions.parameters.size != 0) {
        SetDataParameters(cOptions.parameters, options.parameters);
    }
    if (callbackId.onRequestContinued != nullptr) {
        callback.onRequestContinued = CJLambda::Create(callbackId.onRequestContinued);
    }
    callback.onResult = CJLambda::Create(callbackId.onResult);
    callback.onRequestRedirected = CJLambda::Create(callbackId.onRequestRedirected);
}

int32_t CJAppAccountImpl::setAuthenticatorProperties(
    std::string owner, CAuthCallback callbackId, CSetPropertiesOptions cOptions)
{
    SetPropertiesOptions options;
    JSAuthCallback callback;
    ParseContextForSetAuthenticatorProperties(callbackId, cOptions, callback, options);
    sptr<AppAccountManagerCallback> appAccountMgrCb = new (std::nothrow) AppAccountManagerCallback(callback);
    if (appAccountMgrCb == nullptr) {
        ACCOUNT_LOGD("failed to create AppAccountManagerCallback for insufficient memory");
        AAFwk::Want result;
        std::string value = std::string();
        appAccountMgrCb->OnResult(ERR_CJ_SYSTEM_SERVICE_EXCEPTION, result);
        callback.onResult(ERR_CJ_SYSTEM_SERVICE_EXCEPTION, Convert2CAuthResult(value, value, value, value));
        return ERR_CJ_SYSTEM_SERVICE_EXCEPTION;
    }
    int32_t errCode = ConvertToJSErrCode(
        AppAccountManager::SetAuthenticatorProperties(owner, options, appAccountMgrCb));
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("setAuthenticatorProperties failed");
        AAFwk::Want result;
        std::string value = std::string();
        appAccountMgrCb->OnResult(ERR_CJ_SYSTEM_SERVICE_EXCEPTION, result);
        callback.onResult(ERR_CJ_SYSTEM_SERVICE_EXCEPTION, Convert2CAuthResult(value, value, value, value));
        return errCode;
    }
    // account: AppAccountInfo
    std::string nameResult = appAccountMgrCb->nameResult;
    std::string ownerResult = appAccountMgrCb->ownerResult;
    //tokenInfo: AuthTokenInfo
    std::string authTypeResult = appAccountMgrCb->authTypeResult;
    std::string tokenResult = appAccountMgrCb->tokenResult;
    CAuthResult result = Convert2CAuthResult(nameResult, ownerResult, authTypeResult, tokenResult);
    callback.onResult(errCode, result);
    return errCode;
}

std::map<std::string, std::string> CJAppAccountImpl::ConvertCArr2Map(const CHashStrStrArr &cHeaders)
{
    std::map<std::string, std::string> res;
    for (int64_t i = 0; i < cHeaders.size; ++i) {
        const CHashStrStrPair *cHeader = &cHeaders.headers[i];
        res[cHeader->key] = cHeader->value;
    }
    return res;
}

void CJAppAccountImpl::Convert2CreateAccountOptions(CCreateAccountOptions &in, CreateAccountOptions &out)
{
    out.customData = ConvertCArr2Map(in.customData);
}

CArrAppAccountInfo CJAppAccountImpl::Convert2CArrAppAccountInfo(const std::vector<AppAccountInfo> &in)
{
    CArrAppAccountInfo res{};
    if (in.size() <= 0) {
        return res;
    }
    res.head = static_cast<CAppAccountInfo *>(malloc(sizeof(CAppAccountInfo) * in.size()));
    if (res.head == nullptr) {
        return res;
    }
    size_t i = 0;
    for (auto item : in) {
        std::string owner;
        item.GetOwner(owner);
        res.head[i].owner = MallocCString(owner);
        std::string name;
        item.GetName(name);
        res.head[i].name = MallocCString(name);
        i++;
    }
    res.size = static_cast<int64_t>(i);
    return res;
}

CArrAppAccountInfo CJAppAccountImpl::Convert2CArrAppAccountInfo(
    const std::vector<std::string> &names, const std::vector<std::string> &owners)
{
    CArrAppAccountInfo res{};
    if (names.size() <= 0) {
        return res;
    }
    res.head = static_cast<CAppAccountInfo *>(malloc(sizeof(CAppAccountInfo) * names.size()));
    if (res.head == nullptr) {
        return res;
    }
    size_t i = 0;
    for (; i < names.size(); ++i) {
        CAppAccountInfo tmp;
        tmp.owner = MallocCString(owners[i]);
        tmp.name = MallocCString(names[i]);
        res.head[i] = tmp;
    }
    res.size = static_cast<int64_t>(i);
    return res;
}

CArrAuthTokenInfo CJAppAccountImpl::Convert2CArrAuthTokenInfo(const std::vector<OAuthTokenInfo> &in)
{
    CArrAuthTokenInfo res{};
    if (in.size() <= 0) {
        return res;
    }
    res.head = static_cast<CAuthTokenInfo *>(malloc(sizeof(CAuthTokenInfo) * in.size()));
    if (res.head == nullptr) {
        return res;
    }
    size_t i = 0;
    for (; i < in.size(); ++i) {
        res.head[i].authType = MallocCString(in[i].authType);
        res.head[i].token = MallocCString(in[i].token);
        res.head[i].account.owner = MallocCString(std::string());
        res.head[i].account.name = MallocCString(std::string());
    }
    res.size = static_cast<int64_t>(i);
    return res;
}


std::vector<std::string> CJAppAccountImpl::Convert2VecString(CArrString &in)
{
    std::vector<std::string> ret;
    for (int i = 0; i < in.size; ++i) {
        ret.emplace_back(std::string(in.head[i]));
    }
    return ret;
}

void CJAppAccountImpl::clearCharPointer(char **ptr, int count)
{
    for (int i = 0; i < count; ++i) {
        free(ptr[i]);
    }
}

CArrString CJAppAccountImpl::ConvertSet2CArrString(std::set<std::string> &in)
{
    CArrString arrStr{0};
    if (in.empty()) {
        return arrStr;
    }
    arrStr.size = static_cast<int64_t>(in.size());
    char **retValue = static_cast<char**>(malloc(sizeof(char *) * arrStr.size));
    if (retValue == nullptr) {
        return arrStr;
    }
    size_t i = 0;
    for (auto idx = in.begin(); idx != in.end(); idx++) {
        retValue[i] =  MallocCString(*idx);
        if (retValue[i] == nullptr) {
            clearCharPointer(retValue, i);
            free(retValue);
            return {nullptr, 0};
        }
    }
    arrStr.head = retValue;
    return arrStr;
}

CArrString CJAppAccountImpl::ConvertVec2CArrString(std::vector<std::string> &in)
{
    CArrString arrStr{0};
    if (in.empty()) {
        return arrStr;
    }
    arrStr.size = static_cast<int64_t>(in.size());
    char **retValue = static_cast<char**>(malloc(sizeof(char *) * arrStr.size));
    if (retValue == nullptr) {
        return arrStr;
    }
    for (size_t i = 0; i < in.size(); i++) {
        retValue[i] =  MallocCString(in[i]);
        if (retValue[i] == nullptr) {
            clearCharPointer(retValue, i);
            free(retValue);
            return {nullptr, 0};
        }
    }
    arrStr.head = retValue;
    return arrStr;
}

CAuthenticatorInfo CJAppAccountImpl::Convert2CAuthenticatorInfo(AuthenticatorInfo &in)
{
    CAuthenticatorInfo cInfo{};
    cInfo.owner = MallocCString(in.owner);
    cInfo.iconId = static_cast<int32_t>(in.iconId);
    cInfo.labelId = static_cast<int32_t>(in.labelId);
    return cInfo;
}

std::vector<std::pair<std::string, std::string>> CJAppAccountImpl::Convert2VecAppAccountInfo(CArrAppAccountInfo &in)
{
    std::vector<std::pair<std::string, std::string>> ret;
    for (int i = 0; i < in.size; ++i) {
        ret.push_back({in.head[i].owner, in.head[i].name});
    }
    return ret;
}

void CJAppAccountImpl::Convert2SelectAccountsOptions(CSelectAccountsOptions &in, SelectAccountsOptions &out)
{
    out.allowedAccounts = Convert2VecAppAccountInfo(in.allowedAccounts);
    out.allowedOwners = Convert2VecString(in.allowedOwners);
    out.requiredLabels = Convert2VecString(in.requiredLabels);
}

CAuthResult CJAppAccountImpl::Convert2CAuthResult(
    std::string name, std::string owner, std::string authType, std::string token)
{
    bool flag = true;
    CAuthResult res{};
    CAppAccountInfo account{};
    CAuthTokenInfo tokenInfo{};
    if (name.empty() || owner.empty() || authType.empty() || token.empty()) {
        flag = false;
        res.flag = flag;
        res.account = account;
        res.tokenInfo = tokenInfo;
        return res;
    }
    account.name = MallocCString(name);
    account.owner = MallocCString(owner);
    res.account = account;
    tokenInfo.authType = MallocCString(authType);
    tokenInfo.token = MallocCString(token);
    res.tokenInfo = tokenInfo;
    res.flag = flag;
    return res;
}
} // namespace::OHOS::AccountSA