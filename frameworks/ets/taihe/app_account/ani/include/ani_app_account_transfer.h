/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ANI_APP_ACCOUNT_TRANSFER_H
#define ANI_APP_ACCOUNT_TRANSFER_H

#include <memory>
#include "ani.h"
#include "native_engine/native_engine.h"

namespace OHOS {
namespace AccountSA {
class AniAppAccountTransfer {
public:
    AniAppAccountTransfer() = default;
    ~AniAppAccountTransfer() = default;

    AniAppAccountTransfer(const AniAppAccountTransfer&) = delete;
    AniAppAccountTransfer(AniAppAccountTransfer&&) = delete;
    AniAppAccountTransfer& operator=(const AniAppAccountTransfer&) = delete;
    AniAppAccountTransfer& operator=(AniAppAccountTransfer&&) = delete;

    static ani_object NativeAuthCallbackTransferStatic(ani_env *aniEnv, ani_class aniCls, ani_object input);
    static ani_ref NativeAuthCallbackTransferDynamic(ani_env *aniEnv, ani_class aniCls, ani_object input);
    static ani_object NativeAppAccountManagerTransferStatic(ani_env *aniEnv, ani_class aniCls, ani_object input);
    static ani_ref NativeAppAccountManagerTransferDynamic(ani_env *aniEnv, ani_class aniCls, ani_object input);
private:
    static napi_value JsConstructor(napi_env env, napi_callback_info cbInfo);
    static napi_value CreateAppAccountManager(napi_env env, napi_callback_info cbInfo);
    static ani_ref GenerateAppAccountMangerDynamic(ani_env *aniEnv, uint64_t ptr);
    static ani_ref GenerateCallbackDynamic(ani_env *aniEnv, uint64_t ptr);
    static napi_property_descriptor appAccountProperties[];
};

void AniAppAccountTransferInit(ani_env *aniEnv);
}
}

#endif // ANI_APP_ACCOUNT_TRANSFER_H