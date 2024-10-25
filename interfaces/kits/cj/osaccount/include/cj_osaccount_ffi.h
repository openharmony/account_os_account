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

#ifndef CJ_OSACCOUNT_FFI_H
#define CJ_OSACCOUNT_FFI_H

#include <cstdint>
#include "cj_ffi/cj_common_ffi.h"
#include "ffi_remote_data.h"
#include "common.h"

EXTERN_C_START
FFI_EXPORT bool FfiOHOSOsAccountIsOsAccountConstraintEnabled(char *constraint, int32_t *errCode);
FFI_EXPORT int32_t FfiOHOSOsAccountGetOsAccountType(int32_t *errCode);
FFI_EXPORT bool FfiOHOSOsAccountCheckOsAccountTestable(int32_t *errCode);
FFI_EXPORT bool FfiOHOSOsAccountCheckMultiOsAccountEnabled(int32_t *errCode);
FFI_EXPORT int32_t FfiOHOSOsAccountGetOsAccountLocalId(int32_t *errCode);
FFI_EXPORT RetDataCArrI32 FfiOHOSOsAccountGetActivatedOsAccountLocalIds();
FFI_EXPORT uint32_t FfiOHOSOsAccountGetOsAccountCount(int32_t *errCode);
FFI_EXPORT char* FfiOHOSOsAccountQueryDistributedVirtualDeviceId(int32_t *errCode);
FFI_EXPORT int64_t FfiOHOSOsAccountGetSerialNumberForOsAccountLocalId(int32_t localId, int32_t *errCode);
FFI_EXPORT int32_t FfiOHOSOsAccountGetOsAccountLocalIdForSerialNumber(int64_t serialNumber, int32_t *errCode);
FFI_EXPORT int32_t FfiOHOSOsAccountGetOsAccountLocalIdForDomain(CDomainAccountInfo cDoaminInfo, int32_t *errCode);
FFI_EXPORT int32_t FfiOHOSOsAccountGetOsAccountLocalIdForUid(int32_t uid, int32_t *errCode);
FFI_EXPORT char* FfiOHOSOsAccountGetOsAccountName(int32_t *errCode);
FFI_EXPORT bool FfiOHOSOsAccountIsOsAccountUnlocked(int32_t *errCode);
FFI_EXPORT RetDataI64 FfiOHOSOsAccountGetAccountManager();

EXTERN_C_END

#endif