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


#ifndef APPACCOUNT_FFI_H
#define APPACCOUNT_FFI_H

#include <stdint.h>

#include "cj_common_ffi.h"
#include "ffi_remote_data.h"
#include "appaccount_common.h"
#include "appaccount_defination.h"
#include "appaccount_error.h"
#include "appaccount_impl.h"
#include "appaccount_parameter_parse.h"

#ifndef FFI_EXPORT
#ifndef WINDOWS_PLATFORM
#define FFI_EXPORT __attribute__((visibility("default")))
#else
#define FFI_EXPORT __declspec(dllexport)
#endif
#endif

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

FFI_EXPORT int64_t FfiAppAccountCreateAppAccountManager();
FFI_EXPORT int32_t FfiAppAccountAppAccountManagerCreateAccount(int id, char *name, CCreateAccountOptions options);
FFI_EXPORT int32_t FfiAppAccountAppAccountManagerRemoveAccount(int id, char *name);
FFI_EXPORT int32_t FfiAppAccountAppAccountManagerSetAppAccess(int id, char *name, char *bundleName, bool isAccessible);
FFI_EXPORT RetDataBool FfiAppAccountAppAccountManagerCheckAppAccess(int id, char *name, char *bundleName);
FFI_EXPORT RetDataBool FfiAppAccountAppAccountManagerCheckDataSyncEnabled(int id, char *name);
FFI_EXPORT int32_t FfiAppAccountAppAccountManagerSetCredential(
    int id, char *name, char *credentialType, char *credential);
FFI_EXPORT ErrCArrAppAccountInfo FfiAppAccountAppAccountManagerGetAccountsByOwner(int id, char *owner);
FFI_EXPORT RetDataCString FfiAppAccountAppAccountManagerGetCredential(int id, char *name, char *credentialType);
FFI_EXPORT RetDataCString FfiAppAccountAppAccountManagerGetCustomData(int id, char *name, char *key);
FFI_EXPORT RetDataCString FfiAppAccountAppAccountManagerGetAuthToken(int id, char *name, char *owner, char *authType);
FFI_EXPORT int32_t FfiAppAccountAppAccountManagerSetAuthToken(int id, char *name, char *authType, char *token);
FFI_EXPORT int32_t FfiAppAccountAppAccountManagerDeleteAuthToken(
    int id, char *name, char *owner, char *authType, char *token);
FFI_EXPORT int32_t FfiAppAccountAppAccountManagerSetAuthTokenVisibility(
    int id, char *name, char *authType, char *bundleName, bool isVisible);
FFI_EXPORT RetDataBool FfiAppAccountAppAccountManagerCheckAuthTokenVisibility(
    int id, char *name, char *authType, char *bundleName, bool isVisible);
FFI_EXPORT ErrCArrAuthTokenInfo FfiAppAccountAppAccountManagerGetAllAuthTokens(int id, char *name, char *owner);
FFI_EXPORT RetDataCArrString FfiAppAccountAppAccountManagerGetAuthList(int id, char *name, char *authType);
FFI_EXPORT ErrCAuthenticatorInfo FfiAppAccountAppAccountManagerQueryAuthenticatorInfo(int id, char *owner);
FFI_EXPORT int32_t FfiAppAccountAppAccountManagerDeleteCredential(int id, char *name, char *credentialType);
FFI_EXPORT ErrCArrAppAccountInfo FfiAppAccountAppAccountManagerGetAllAccounts(int id);
FFI_EXPORT int32_t FfiAppAccountAppAccountManagerSetCustomData(int id, char *name, char *key, char *value);
FFI_EXPORT int32_t FfiAppAccountAppAccountManagerSetDataSyncEnabled(int id, char *name, bool isEnabled);
FFI_EXPORT int32_t FfiAppAccountAppAccountManagerOn(
    int id, char *type, CArrString owners, void (*callback)(CArrAppAccountInfo cArrAppAccountInfo));
FFI_EXPORT int32_t FfiAppAccountAppAccountManagerOff(
    int id, char *type, void (*callback)(CArrAppAccountInfo cArrAppAccountInfo));
FFI_EXPORT int32_t FfiAppAccountAppAccountManagerCheckAccountLabels(
    int id, char *name, char *owner, CArrString labels, void (*callback)(RetDataBool infoRef));
FFI_EXPORT int32_t FfiAppAccountAppAccountManagerSelectAccountsByOptions(
    int id, CSelectAccountsOptions cOptions, void (*callback)(ErrCArrAppAccountInfo infoRef));
FFI_EXPORT int32_t FfiAppAccountAppAccountManagerVerifyCredential(
    int id, char *name, char *owner, CAuthCallback callbackId, CVerifyCredentialOptions cOptions);
FFI_EXPORT int32_t FfiAppAccountAppAccountManagerSetAuthenticatorProperties(
    int id, char *owner, CAuthCallback callbackId, CSetPropertiesOptions cOptions);
}
#endif