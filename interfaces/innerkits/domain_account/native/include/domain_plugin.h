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

#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_ACCOUNT_LIB_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_ACCOUNT_LIB_H
#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char* data;
    size_t length;
} PluginString;

typedef struct {
    uint8_t* data;
    size_t size;
    size_t capcity;
} PluginUint8Vector;

typedef struct {
    int32_t code;
    PluginString msg;
} PluginBussnessError;

typedef struct {
    PluginString id;
    PluginString domain;
    PluginString parameters;
} PluginServerConfigInfo;

typedef struct {
    PluginString serverConfigId;
    PluginString domain;
    PluginString accountName;
    PluginString accountId;
    int32_t isAuthenticated;
} PluginDomainAccountInfo;

typedef struct {
    PluginUint8Vector accountToken;
    int32_t remainTimes;
    int32_t freezingTime;
} PluginAuthResultInfo;

typedef struct {
    PluginDomainAccountInfo domainAccountInfo;
    int32_t callerUid;
} PluginGetDomainAccountInfoOptions;

typedef struct {
    int32_t remainTimes;
    int32_t freezingTime;
} PluginAuthStatusInfo;

typedef struct {
    PluginDomainAccountInfo domainAccountInfo;
    PluginUint8Vector domainAccountToken;
    PluginString bussinessParams;
    int32_t callerUid;
} PluginGetDomainAccessTokenOptions;

typedef struct {
    int32_t authenicationValidityPeriod;
} PluginDomainAccountPolicy;

typedef PluginBussnessError* (*AddServerConfigFunc)(const PluginString *parameters, const int32_t callerLocalId,
    PluginServerConfigInfo **serverConfigInfo);
typedef PluginBussnessError* (*RemoveServerConfigFunc)(const PluginString *serverConfigId, const int32_t callerLocalId);
typedef PluginBussnessError* (*GetAccountServerConfigFunc)(const PluginDomainAccountInfo *domainAccountInfo,
    PluginServerConfigInfo **serverConfigInfo);
typedef PluginBussnessError* (*AuthFunc)(const PluginDomainAccountInfo *domainAccountInfo,
    const PluginUint8Vector *credential, const int32_t callerLocalId, PluginAuthResultInfo **authResultInfo);
typedef PluginBussnessError* (*AuthWithPopupFunc)(const PluginDomainAccountInfo *domainAccountInfo,
    PluginAuthResultInfo **authResultInfo);
typedef PluginBussnessError* (*AuthWithTokenFunc)(const PluginDomainAccountInfo *domainAccountInfo,
    const PluginUint8Vector *token, PluginAuthResultInfo **authResultInfo);
typedef PluginBussnessError* (*GetAccountInfoFunc)(const PluginGetDomainAccountInfoOptions *options,
    const int32_t callerLocalId, PluginDomainAccountInfo **domainAccountInfo);
typedef PluginBussnessError* (*GetAuthStatusInfoFunc)(const PluginDomainAccountInfo *domainAccountInfo,
    PluginAuthStatusInfo **authStatusInfo);
typedef PluginBussnessError* (*BindAccountFunc)(const PluginDomainAccountInfo *domainAccountInfo, const int32_t localId,
    const int32_t callerLocalId);
typedef PluginBussnessError* (*UnbindAccountFunc)(const PluginDomainAccountInfo *domainAccountInfo);
typedef PluginBussnessError* (*UpdateAccountInfoFunc)(const PluginDomainAccountInfo *domainAccountInfo,
    const PluginDomainAccountInfo *newDomainAccountInfo);
typedef PluginBussnessError* (*IsAccountTokenValidFunc)(const PluginDomainAccountInfo *domainAccountInfo,
    const PluginUint8Vector *token, int32_t *isValid);
typedef PluginBussnessError* (*IsAuthenticationExpiredFunc)(const PluginDomainAccountInfo *domainAccountInfo,
    const PluginUint8Vector *token, int32_t *isValid);
typedef PluginBussnessError* (*GetAccessTokenFunc)(const PluginGetDomainAccessTokenOptions *options,
    PluginUint8Vector **accessToken);
typedef PluginBussnessError* (*SetAccountPolicyFunc)(const PluginDomainAccountPolicy *domainAccountPolicy);
typedef PluginBussnessError* (*GetServerConfigFunc)(const PluginString *serverConfigId, const int32_t callerLocalId,
    PluginServerConfigInfo **serverConfigInfo);

enum PluginMethodEnum {
    ADD_SERVER_CONFIG = 0,
    REMOVE_SERVER_CONFIG,
    GET_ACCOUNT_SERVER_CONFIG,
    AUTH,
    AUTH_WITH_POPUP,
    AUTH_WITH_TOKEN,
    GET_ACCOUNT_INFO,
    GET_AUTH_STATUS_INFO,
    BIND_ACCOUNT,
    UNBIND_ACCOUNT,
    IS_ACCOUNT_TOKEN_VALID,
    GET_ACCESS_TOKEN,
    GET_SERVER_CONFIG,
    UPDATE_ACCOUNT_INFO,
    IS_AUTHENTICATION_EXPIRED,
    SET_ACCOUNT_POLICY,
    //this is last just for count enum
    COUNT,
};

#ifdef __cplusplus
}
#endif
#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_ACCOUNT_LIB_H