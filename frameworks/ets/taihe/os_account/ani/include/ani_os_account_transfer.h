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

#ifndef ANI_OS_ACCOUNT_TRANSFER_H
#define ANI_OS_ACCOUNT_TRANSFER_H

#include <memory>
#include "ani.h"
#include "native_engine/native_engine.h"

namespace OHOS {
namespace AccountSA {
class AniOsAccountTransfer {
public:
    AniOsAccountTransfer() = default;
    ~AniOsAccountTransfer() = default;

    AniOsAccountTransfer(const AniOsAccountTransfer&) = delete;
    AniOsAccountTransfer(AniOsAccountTransfer&&) = delete;
    AniOsAccountTransfer& operator=(const AniOsAccountTransfer&) = delete;
    AniOsAccountTransfer& operator=(AniOsAccountTransfer&&) = delete;

    static ani_object NativeIInputDataTransferStatic(ani_env *aniEnv, ani_class aniCls, ani_object input);
    static ani_ref NativeIInputDataTransferDynamic(ani_env *aniEnv, ani_class aniCls, ani_object input);
private:
};

void AniOsAccountTransferInit(ani_env *aniEnv);
}
}

#endif ANI_OS_ACCOUNT_TRANSFER_H