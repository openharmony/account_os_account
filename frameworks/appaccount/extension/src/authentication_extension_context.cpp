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

#include "authentication_extension_context.h"

#include "ability_connection.h"
#include "ability_manager_client.h"
#include "account_log_wrapper.h"

using namespace OHOS::AccountSA;
namespace OHOS {
namespace AbilityRuntime {
const size_t AuthenticationExtensionContext::CONTEXT_TYPE_ID(
    std::hash<const char *>{}("AuthenticationExtensionContext"));
int AuthenticationExtensionContext::ILLEGAL_REQUEST_CODE(-1);

ErrCode AuthenticationExtensionContext::StartModalDialogForResult(const AAFwk::Want &want) const
{
    return ERR_OK;
}
} // namespace AbilityRuntime
} // namespace OHOS