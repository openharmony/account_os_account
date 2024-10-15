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


#ifndef APPACCOUNT_DEFINATION_H
#define APPACCOUNT_DEFINATION_H

#include "cj_common_ffi.h"

using WantHandle = void*;
typedef struct {
    char *key;
    char *value;
} CHashStrStrPair;

typedef struct {
    CHashStrStrPair *headers;
    int64_t size;
} CHashStrStrArr;

typedef struct {
    CHashStrStrArr customData;
} CCreateAccountOptions;

typedef struct {
    char *owner;
    char *name;
} CAppAccountInfo;

typedef struct {
    CAppAccountInfo *head;
    int64_t size;
} CArrAppAccountInfo;

typedef struct {
    char *authType;
    char *token;
    CAppAccountInfo account;
} CAuthTokenInfo;

typedef struct {
    CAuthTokenInfo *head;
    int64_t size;
} CArrAuthTokenInfo;

typedef struct {
    char *owner;
    int32_t iconId;
    int32_t labelId;
} CAuthenticatorInfo;

typedef struct {
    CArrAppAccountInfo allowedAccounts;
    CArrString allowedOwners;
    CArrString requiredLabels;
} CSelectAccountsOptions;

typedef struct {
    int32_t err;
    CArrAppAccountInfo cArrAppAccountInfo;
} ErrCArrAppAccountInfo;

typedef struct {
    int32_t err;
    CArrAuthTokenInfo cArrAuthTokenInfo;
} ErrCArrAuthTokenInfo;

typedef struct {
    int32_t err;
    CAuthenticatorInfo cAuthenticatorInfo;
} ErrCAuthenticatorInfo;

typedef struct {
    CAppAccountInfo account;
    CAuthTokenInfo tokenInfo;
    bool flag;
} CAuthResult;

typedef struct {
    int8_t valueType;
    char *key;
    void *value;
    int64_t size;
} CParameters;

typedef struct {
    CParameters *head;
    int64_t size;
} CArrParameters;

typedef struct {
    char *credentialType;
    char *credential;
    CArrParameters parameters;
} CVerifyCredentialOptions;

typedef struct {
    CArrParameters properties;
    CArrParameters parameters;
} CSetPropertiesOptions;

typedef struct {
    CArrString reruiredLabels;
    char *authType;
    CArrParameters parameters;
} CCreateAccountImplicityOptions;

typedef struct {
    void(*onResult) (int32_t, CAuthResult);
    void(*onRequestRedirected) (WantHandle);
    void(*onRequestContinued) ();
} CAuthCallback;

namespace OHOS::AccountSA {
    char *MallocCString(const std::string &origin);
    char *MallocCString(const std::string &origin, int32_t &code);
} // namespace OHOS::AccountSA
#endif