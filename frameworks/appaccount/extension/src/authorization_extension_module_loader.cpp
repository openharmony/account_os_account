/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "authorization_extension_module_loader.h"

#include "account_log_wrapper.h"
#include "authorization_extension.h"

using namespace OHOS::AccountSA;
namespace {
const std::map<std::string, std::string> g_params = {{"type", "258"}, {"name", "AppAccountAuthorizationExtension"}};
}
namespace OHOS::AbilityRuntime {
AuthorizationExtensionModuleLoader::AuthorizationExtensionModuleLoader() = default;
AuthorizationExtensionModuleLoader::~AuthorizationExtensionModuleLoader() = default;

Extension *AuthorizationExtensionModuleLoader::Create(const std::unique_ptr<Runtime> &runtime) const
{
    return AuthorizationExtension::Create(runtime);
}

std::map<std::string, std::string> AuthorizationExtensionModuleLoader::GetParams()
{
    return g_params;
}

extern "C" __attribute__((visibility("default"))) void *OHOS_EXTENSION_GetExtensionModule()
{
    return &AuthorizationExtensionModuleLoader::GetInstance();
}
} // namespace OHOS::AbilityRuntime