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

#include "appaccount_ffi.h"

#include "cj_lambda.h"
#include "appaccount_impl.h"

using namespace OHOS::FFI;

namespace OHOS::AccountSA {
extern "C" {
int64_t FfiAppAccountCreateAppAccountManager()
{
    auto nativeAppAccountManager = FFIData::Create<CJAppAccountImpl>();
    if (nativeAppAccountManager == nullptr) {
        return ERR_CJ_SYSTEM_SERVICE_EXCEPTION;
    }
    return nativeAppAccountManager->GetID();
}

int32_t FfiAppAccountAppAccountManagerCreateAccount(int id, char *name, CCreateAccountOptions options)
{
    auto instance = FFIData::GetData<CJAppAccountImpl>(id);
    if (!instance) {
        return ERR_CJ_SYSTEM_SERVICE_EXCEPTION;
    }
    return instance->createAccount(name, options);
}

int32_t FfiAppAccountAppAccountManagerRemoveAccount(int id, char *name)
{
    auto instance = FFIData::GetData<CJAppAccountImpl>(id);
    if (!instance) {
        return ERR_CJ_SYSTEM_SERVICE_EXCEPTION;
    }
    return instance->removeAccount(name);
}

int32_t FfiAppAccountAppAccountManagerSetAppAccess(int id, char *name, char *bundleName, bool isAccessible)
{
    auto instance = FFIData::GetData<CJAppAccountImpl>(id);
    if (!instance) {
        return ERR_CJ_SYSTEM_SERVICE_EXCEPTION;
    }
    return instance->setAppAccess(name, bundleName, isAccessible);
}

RetDataBool FfiAppAccountAppAccountManagerCheckAppAccess(int id, char *name, char *bundleName)
{
    auto instance = FFIData::GetData<CJAppAccountImpl>(id);
    if (!instance) {
        return {ERR_CJ_SYSTEM_SERVICE_EXCEPTION, false};
    }
    return instance->checkAppAccess(name, bundleName);
}

RetDataBool FfiAppAccountAppAccountManagerCheckDataSyncEnabled(int id, char *name)
{
    auto instance = FFIData::GetData<CJAppAccountImpl>(id);
    if (!instance) {
        return {ERR_CJ_SYSTEM_SERVICE_EXCEPTION, false};
    }
    return instance->checkDataSyncEnabled(name);
}

int32_t FfiAppAccountAppAccountManagerSetCredential(int id, char *name, char *credentialType, char *credential)
{
    auto instance = FFIData::GetData<CJAppAccountImpl>(id);
    if (!instance) {
        return ERR_CJ_SYSTEM_SERVICE_EXCEPTION;
    }
    return instance->setCredential(name, credentialType, credential);
}

ErrCArrAppAccountInfo FfiAppAccountAppAccountManagerGetAccountsByOwner(int id, char *owner)
{
    auto instance = FFIData::GetData<CJAppAccountImpl>(id);
    if (!instance) {
        ErrCArrAppAccountInfo res{};
        res.err = ERR_CJ_SYSTEM_SERVICE_EXCEPTION;
        return res;
    }
    return instance->getAccountsByOwner(owner);
}

RetDataCString FfiAppAccountAppAccountManagerGetCredential(int id, char *name, char *credentialType)
{
    auto instance = FFIData::GetData<CJAppAccountImpl>(id);
    if (!instance) {
        RetDataCString ret = { .code = ERR_CJ_SYSTEM_SERVICE_EXCEPTION, .data = nullptr };
        return ret;
    }
    return instance->getCredential(name, credentialType);
}

RetDataCString FfiAppAccountAppAccountManagerGetCustomData(int id, char *name, char *key)
{
    auto instance = FFIData::GetData<CJAppAccountImpl>(id);
    if (!instance) {
        RetDataCString ret = { .code = ERR_CJ_SYSTEM_SERVICE_EXCEPTION, .data = nullptr };
        return ret;
    }
    return instance->getCustomData(name, key);
}

RetDataCString FfiAppAccountAppAccountManagerGetAuthToken(int id, char *name, char *owner, char *authType)
{
    auto instance = FFIData::GetData<CJAppAccountImpl>(id);
    if (!instance) {
        RetDataCString ret = { .code = ERR_CJ_SYSTEM_SERVICE_EXCEPTION, .data = nullptr };
        return ret;
    }
    return instance->getAuthToken(name, owner, authType);
}

int32_t FfiAppAccountAppAccountManagerSetAuthToken(int id, char *name, char *authType, char *token)
{
    auto instance = FFIData::GetData<CJAppAccountImpl>(id);
    if (!instance) {
        return ERR_CJ_SYSTEM_SERVICE_EXCEPTION;
    }
    return instance->setAuthToken(name, authType, token);
}

int32_t FfiAppAccountAppAccountManagerDeleteAuthToken(int id, char *name, char *owner, char *authType, char *token)
{
    auto instance = FFIData::GetData<CJAppAccountImpl>(id);
    if (!instance) {
        return ERR_CJ_SYSTEM_SERVICE_EXCEPTION;
    }
    return instance->deleteAuthToken(name, owner, authType, token);
}

int32_t FfiAppAccountAppAccountManagerSetAuthTokenVisibility(
    int id, char *name, char *authType, char *bundleName, bool isVisible)
{
    auto instance = FFIData::GetData<CJAppAccountImpl>(id);
    if (!instance) {
        return ERR_CJ_SYSTEM_SERVICE_EXCEPTION;
    }
    return instance->setAuthTokenVisibility(name, authType, bundleName, isVisible);
}

RetDataBool FfiAppAccountAppAccountManagerCheckAuthTokenVisibility(
    int id, char *name, char *authType, char *bundleName, bool isVisible)
{
    auto instance = FFIData::GetData<CJAppAccountImpl>(id);
    if (!instance) {
        return {ERR_CJ_SYSTEM_SERVICE_EXCEPTION, false};
    }
    return instance->checkAuthTokenVisibility(name, authType, bundleName);
}

ErrCArrAuthTokenInfo FfiAppAccountAppAccountManagerGetAllAuthTokens(int id, char *name, char *owner)
{
    auto instance = FFIData::GetData<CJAppAccountImpl>(id);
    if (!instance) {
        ErrCArrAuthTokenInfo res{};
        res.err = ERR_CJ_SYSTEM_SERVICE_EXCEPTION;
        return res;
    }
    return instance->getAllAuthTokens(name, owner);
}

RetDataCArrString FfiAppAccountAppAccountManagerGetAuthList(int id, char *name, char *authType)
{
    auto instance = FFIData::GetData<CJAppAccountImpl>(id);
    if (!instance) {
        RetDataCArrString res = { .code = ERR_CJ_SYSTEM_SERVICE_EXCEPTION, .data = {.head = nullptr, .size = 0}};
        return res;
    }
    return instance->getAuthList(name, authType);
}

ErrCAuthenticatorInfo FfiAppAccountAppAccountManagerQueryAuthenticatorInfo(int id, char *owner)
{
    auto instance = FFIData::GetData<CJAppAccountImpl>(id);
    if (!instance) {
        ErrCAuthenticatorInfo res{};
        res.err = ERR_CJ_SYSTEM_SERVICE_EXCEPTION;
        return res;
    }
    return instance->queryAuthenticatorInfo(owner);
}

int32_t FfiAppAccountAppAccountManagerDeleteCredential(int id, char *name, char *credentialType)
{
    auto instance = FFIData::GetData<CJAppAccountImpl>(id);
    if (!instance) {
        return ERR_CJ_SYSTEM_SERVICE_EXCEPTION;
    }
    return instance->deleteCredential(name, credentialType);
}

ErrCArrAppAccountInfo FfiAppAccountAppAccountManagerGetAllAccounts(int id)
{
    auto instance = FFIData::GetData<CJAppAccountImpl>(id);
    if (!instance) {
        ErrCArrAppAccountInfo res{};
        res.err = ERR_CJ_SYSTEM_SERVICE_EXCEPTION;
        return res;
    }
    return instance->getAllAccounts();
}

int32_t FfiAppAccountAppAccountManagerSetCustomData(int id, char *name, char *key, char *value)
{
    auto instance = FFIData::GetData<CJAppAccountImpl>(id);
    if (!instance) {
        return ERR_CJ_SYSTEM_SERVICE_EXCEPTION;
    }
    return instance->setCustomData(name, key, value);
}

int32_t FfiAppAccountAppAccountManagerSetDataSyncEnabled(int id, char *name, bool isEnabled)
{
    auto instance = FFIData::GetData<CJAppAccountImpl>(id);
    if (!instance) {
        return ERR_CJ_SYSTEM_SERVICE_EXCEPTION;
    }
    return instance->setDataSyncEnabled(name, isEnabled);
}

int32_t FfiAppAccountAppAccountManagerOn(
    int id, char *type, CArrString owners, void (*callback)(CArrAppAccountInfo cArrAppAccountInfo))
{
    auto instance = FFIData::GetData<CJAppAccountImpl>(id);
    if (!instance) {
        return ERR_CJ_SYSTEM_SERVICE_EXCEPTION;
    }
    return instance->on(type, owners, callback);
}

int32_t FfiAppAccountAppAccountManagerOff(int id, char *type, void (*callback)(CArrAppAccountInfo cArrAppAccountInfo))
{
    auto instance = FFIData::GetData<CJAppAccountImpl>(id);
    if (!instance) {
        return ERR_CJ_SYSTEM_SERVICE_EXCEPTION;
    }
    return instance->off(type, callback);
}

int32_t FfiAppAccountAppAccountManagerCheckAccountLabels(
    int id, char *name, char *owner, CArrString labels, void (*callback)(RetDataBool infoRef))
{
    auto instance = FFIData::GetData<CJAppAccountImpl>(id);
    if (!instance) {
        return ERR_CJ_SYSTEM_SERVICE_EXCEPTION;
    }
    auto onChange = [lambda = CJLambda::Create(callback)]
        (RetDataBool infoRef) -> void { lambda(infoRef); };
    return instance->checkAccountLabels(name, owner, labels, onChange);
}

int32_t FfiAppAccountAppAccountManagerSelectAccountsByOptions(
    int id, CSelectAccountsOptions cOptions, void (*callback)(ErrCArrAppAccountInfo infoRef))
{
    auto instance = FFIData::GetData<CJAppAccountImpl>(id);
    if (!instance) {
        return ERR_CJ_SYSTEM_SERVICE_EXCEPTION;
    }
    auto onChange = [lambda = CJLambda::Create(callback)]
        (ErrCArrAppAccountInfo infoRef) -> void { lambda(infoRef); };
    return instance->selectAccountByOptions(cOptions, onChange);
}

int32_t FfiAppAccountAppAccountManagerVerifyCredential(
    int id, char *name, char *owner, CAuthCallback callbackId, CVerifyCredentialOptions cOptions)
{
    auto instance = FFIData::GetData<CJAppAccountImpl>(id);
    if (!instance) {
        return ERR_CJ_SYSTEM_SERVICE_EXCEPTION;
    }
    return instance->verifyCredential(name, owner, callbackId, cOptions);
}

int32_t FfiAppAccountAppAccountManagerSetAuthenticatorProperties(
    int id, char *owner, CAuthCallback callbackId, CSetPropertiesOptions cOptions)
{
    auto instance = FFIData::GetData<CJAppAccountImpl>(id);
    if (!instance) {
        return ERR_CJ_SYSTEM_SERVICE_EXCEPTION;
    }
    return instance->setAuthenticatorProperties(owner, callbackId, cOptions);
}
}
} // namespace::OHOS::AccountSA