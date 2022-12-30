/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_INTERFACES_KITS_NAPI_IAM_INCLUDE_NAPI_IAM_CONSTANT_H
#define OS_ACCOUNT_INTERFACES_KITS_NAPI_IAM_INCLUDE_NAPI_IAM_CONSTANT_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace AccountJsKit {

enum AuthSubType {
    FACE_2D = 20000,
    FACE_3D = 20001,
};

enum AuthMethod {
    PIN_ONLY = 0xF,
    FACE_ONLY = 0xF0
};

enum Module {
    FACE_AUTH = 1
};

enum FaceTipsCode {
    FACE_AUTH_TIP_TOO_BRIGHT = 1,
    FACE_AUTH_TIP_TOO_DARK = 2,
    FACE_AUTH_TIP_TOO_CLOSE = 3,
    FACE_AUTH_TIP_TOO_FAR = 4,
    FACE_AUTH_TIP_TOO_HIGH = 5,
    FACE_AUTH_TIP_TOO_LOW = 6,
    FACE_AUTH_TIP_TOO_RIGHT = 7,
    FACE_AUTH_TIP_TOO_LEFT = 8,
    FACE_AUTH_TIP_TOO_MUCH_MOTION = 9,
    FACE_AUTH_TIP_POOR_GAZE = 10,
    FACE_AUTH_TIP_NOT_DETECTED = 11,
};

enum FingerprintTips {
    FINGERPRINT_AUTH_TIP_GOOD = 0,
    FINGERPRINT_AUTH_TIP_IMAGER_DIRTY = 1,
    FINGERPRINT_AUTH_TIP_INSUFFICIENT = 2,
    FINGERPRINT_AUTH_TIP_PARTIAL = 3,
    FINGERPRINT_AUTH_TIP_TOO_FAST = 4,
    FINGERPRINT_AUTH_TIP_TOO_SLOW = 5
};

enum GetPropertyType : uint32_t {
    AUTH_SUB_TYPE = 1,
    REMAIN_TIMES = 2,
    FREEZING_TIME = 3,
};

enum SetPropertyType : uint32_t {
    INIT_ALGORITHM = 1,
    FREEZE_TEMPLATE = 2,
    THAW_TEMPLATE = 3,
};

enum class AuthenticationResult {
    NO_SUPPORT = -1,
    SUCCESS = 0,
    COMPARE_FAILURE = 1,
    CANCELED = 2,
    TIMEOUT = 3,
    CAMERA_FAIL = 4,
    BUSY = 5,
    INVALID_PARAMETERS = 6,
    LOCKED = 7,
    NOT_ENROLLED = 8,
    GENERAL_ERROR = 100,
};

class NapiAccountIAMConstant {
public:
    static napi_value Init(napi_env env, napi_value exports);
};
}  // namespace AccountJsKit
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_KITS_NAPI_IAM_INCLUDE_NAPI_IAM_CONSTANT_H