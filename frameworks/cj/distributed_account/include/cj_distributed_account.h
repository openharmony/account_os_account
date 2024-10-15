/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef CJ_DISTRIBUTED_ACCOUNT_FFI_H
#define CJ_DISTRIBUTED_ACCOUNT_FFI_H

#include "ffi_remote_data.h"

namespace OHOS {
namespace AccountSA {
struct RetDistributedInfo {
    char *name;
    char *id;
    char *event;
    char *nickname;
    char *avatar;
    int32_t status;
};

extern "C"
{
FFI_EXPORT RetDistributedInfo FfiOHOSDistributedAccountDistributedInfoGetOsAccountDistributedInfo(int32_t *errCode);

FFI_EXPORT void FfiOHOSDistributedAccountUnitSetOsAccountDistributedInfo(RetDistributedInfo retInfo, int32_t *errCode);
}
}  // namespace AccountSA
}  // namespace OHOS

#endif
