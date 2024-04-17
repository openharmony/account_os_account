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

#ifndef MOCK_DOMAIN_SO_PLUGIN_H
#define MOCK_DOMAIN_SO_PLUGIN_H

#include <cstdint>
#include "domain_plugin.h"

#ifdef __cplusplus
extern "C" {
#endif
PluginBussnessError *Auth(const PluginDomainAccountInfo *domainAccountInfo, const PluginUint8Vector *credential,
                          const int32_t callerLocalId, PluginAuthResultInfo **authResultInfo);
PluginBussnessError *BindAccount(const PluginDomainAccountInfo *domainAccountInfo, const int32_t localId);
PluginBussnessError *GetAccountInfo(const PluginGetDomainAccountInfoOptions *options, const int32_t callerLocalId,
                                    PluginDomainAccountInfo **domainAccountInfo);
PluginBussnessError *IsAuthenticationExpired(const PluginDomainAccountInfo *domainAccountInfo,
                                             const PluginUint8Vector *token, int32_t *isValid);
PluginBussnessError *SetAccountPolicy(PluginDomainAccountPolicy *domainAccountPolicy);
PluginBussnessError *UpdateAccountInfo(const PluginDomainAccountInfo *domainAccountInfo,
                                       const PluginDomainAccountInfo *newDomainAccountInfo);
#ifdef __cplusplus
}
#endif

#endif // MOCK_DOMAIN_SO_PLUGIN_H