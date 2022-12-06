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

#include "napi_account_iam_constant.h"

#include "account_log_wrapper.h"
#include "napi_account_iam_common.h"

namespace OHOS {
namespace AccountJsKit {
using namespace OHOS::AccountSA;

napi_value AuthTypeConstructor(napi_env env)
{
    napi_value authType = nullptr;
    napi_value pin = nullptr;
    napi_value face = nullptr;
    napi_value fingerPrint = nullptr;
    napi_value domain = nullptr;
    NAPI_CALL(env, napi_create_object(env, &authType));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AuthType::PIN), &pin));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AuthType::FACE), &face));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AuthType::FINGERPRINT), &fingerPrint));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(IAMAuthType::DOMAIN), &domain));
    NAPI_CALL(env, napi_set_named_property(env, authType, "PIN", pin));
    NAPI_CALL(env, napi_set_named_property(env, authType, "FACE", face));
    NAPI_CALL(env, napi_set_named_property(env, authType, "FINGERPRINT", fingerPrint));
    NAPI_CALL(env, napi_set_named_property(env, authType, "DOMAIN", domain));
    return authType;
}

napi_value AuthSubTypeConstructor(napi_env env)
{
    napi_value authSubType = nullptr;
    napi_value pinSix = nullptr;
    napi_value pinNumber = nullptr;
    napi_value pinMixed = nullptr;
    napi_value face2d = nullptr;
    napi_value face3d = nullptr;
    napi_value domainMixed = nullptr;
    NAPI_CALL(env, napi_create_object(env, &authSubType));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(PinSubType::PIN_SIX), &pinSix));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(PinSubType::PIN_NUMBER), &pinNumber));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(PinSubType::PIN_MIXED), &pinMixed));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(FACE_2D), &face2d));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(FACE_3D), &face3d));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(IAMAuthSubType::DOMAIN_MIXED), &domainMixed));
    NAPI_CALL(env, napi_set_named_property(env, authSubType, "PIN_SIX", pinSix));
    NAPI_CALL(env, napi_set_named_property(env, authSubType, "PIN_NUMBER", pinNumber));
    NAPI_CALL(env, napi_set_named_property(env, authSubType, "PIN_MIXED", pinMixed));
    NAPI_CALL(env, napi_set_named_property(env, authSubType, "FACE_2D", face2d));
    NAPI_CALL(env, napi_set_named_property(env, authSubType, "FACE_3D", face3d));
    NAPI_CALL(env, napi_set_named_property(env, authSubType, "DOMAIN_MIXED", domainMixed));
    return authSubType;
}

napi_value AuthTrustLevelConstructor(napi_env env)
{
    napi_value authTrustLevel = nullptr;
    napi_value atl1 = nullptr;
    napi_value atl2 = nullptr;
    napi_value atl3 = nullptr;
    napi_value atl4 = nullptr;
    NAPI_CALL(env, napi_create_object(env, &authTrustLevel));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AuthTrustLevel::ATL1), &atl1));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AuthTrustLevel::ATL2), &atl2));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AuthTrustLevel::ATL3), &atl3));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AuthTrustLevel::ATL4), &atl4));
    NAPI_CALL(env, napi_set_named_property(env, authTrustLevel, "ATL1", atl1));
    NAPI_CALL(env, napi_set_named_property(env, authTrustLevel, "ATL2", atl2));
    NAPI_CALL(env, napi_set_named_property(env, authTrustLevel, "ATL3", atl3));
    NAPI_CALL(env, napi_set_named_property(env, authTrustLevel, "ATL4", atl4));
    return authTrustLevel;
}

napi_value GetPropertyTypeConstructor(napi_env env)
{
    napi_value getPropertyType = nullptr;
    napi_value authSubType = nullptr;
    napi_value remainTimes = nullptr;
    napi_value freezingTime = nullptr;
    NAPI_CALL(env, napi_create_object(env, &getPropertyType));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(GetPropertyType::AUTH_SUB_TYPE), &authSubType));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(GetPropertyType::REMAIN_TIMES), &remainTimes));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(GetPropertyType::FREEZING_TIME), &freezingTime));
    NAPI_CALL(env, napi_set_named_property(env, getPropertyType, "AUTH_SUB_TYPE", authSubType));
    NAPI_CALL(env, napi_set_named_property(env, getPropertyType, "REMAIN_TIMES", remainTimes));
    NAPI_CALL(env, napi_set_named_property(env, getPropertyType, "FREEZING_TIME", freezingTime));
    return getPropertyType;
}

napi_value SetPropertyTypeConstructor(napi_env env)
{
    napi_value setPropertyType = nullptr;
    napi_value initAlgorithm = nullptr;
    NAPI_CALL(env, napi_create_object(env, &setPropertyType));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(SetPropertyType::INIT_ALGORITHM), &initAlgorithm));
    NAPI_CALL(env, napi_set_named_property(env, setPropertyType, "INIT_ALGORITHM", initAlgorithm));
    return setPropertyType;
}

napi_value AuthMethodConstructor(napi_env env)
{
    napi_value authMethod = nullptr;
    napi_value pinOnly = nullptr;
    napi_value faceOnly = nullptr;
    NAPI_CALL(env, napi_create_object(env, &authMethod));
    NAPI_CALL(env, napi_create_int32(env, AuthMethod::PIN_ONLY, &pinOnly));
    NAPI_CALL(env, napi_create_int32(env, AuthMethod::FACE_ONLY, &faceOnly));
    NAPI_CALL(env, napi_set_named_property(env, authMethod, "PIN_ONLY", pinOnly));
    NAPI_CALL(env, napi_set_named_property(env, authMethod, "FACE_ONLY", faceOnly));
    return authMethod;
}

napi_value ModuleConstructor(napi_env env)
{
    napi_value module = nullptr;
    napi_value faceAuth = nullptr;
    NAPI_CALL(env, napi_create_object(env, &module));
    NAPI_CALL(env, napi_create_int32(env, Module::FACE_AUTH, &faceAuth));
    NAPI_CALL(env, napi_set_named_property(env, module, "FACE_AUTH", faceAuth));
    return module;
}

napi_value ResultCodeConstructor(napi_env env)
{
    napi_value resultCode = nullptr;
    napi_value success = nullptr;
    napi_value fail = nullptr;
    napi_value generalError = nullptr;
    napi_value canceled = nullptr;
    napi_value timeout = nullptr;
    napi_value typeNotSupport = nullptr;
    napi_value trustLevelNotSupport = nullptr;
    napi_value busy = nullptr;
    napi_value invalidParameters = nullptr;
    napi_value locked = nullptr;
    napi_value notEnrolled = nullptr;
    NAPI_CALL(env, napi_create_object(env, &resultCode));
    NAPI_CALL(env, napi_create_int32(env, ResultCode::SUCCESS, &success));
    NAPI_CALL(env, napi_create_int32(env, ResultCode::FAIL, &fail));
    NAPI_CALL(env, napi_create_int32(env, ResultCode::GENERAL_ERROR, &generalError));
    NAPI_CALL(env, napi_create_int32(env, ResultCode::CANCELED, &canceled));
    NAPI_CALL(env, napi_create_int32(env, ResultCode::TIMEOUT, &timeout));
    NAPI_CALL(env, napi_create_int32(env, ResultCode::TYPE_NOT_SUPPORT, &typeNotSupport));
    NAPI_CALL(env, napi_create_int32(env, ResultCode::TRUST_LEVEL_NOT_SUPPORT, &trustLevelNotSupport));
    NAPI_CALL(env, napi_create_int32(env, ResultCode::BUSY, &busy));
    NAPI_CALL(env, napi_create_int32(env, ResultCode::INVALID_PARAMETERS, &invalidParameters));
    NAPI_CALL(env, napi_create_int32(env, ResultCode::LOCKED, &locked));
    NAPI_CALL(env, napi_create_int32(env, ResultCode::NOT_ENROLLED, &notEnrolled));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "SUCCESS", success));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "FAIL", fail));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "GENERAL_ERROR", generalError));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "CANCELED", canceled));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "TIMEOUT", timeout));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "TYPE_NOT_SUPPORT", typeNotSupport));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "TRUST_LEVEL_NOT_SUPPORT", trustLevelNotSupport));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "BUSY", busy));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "INVALID_PARAMETERS", invalidParameters));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "LOCKED", locked));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "NOT_ENROLLED", notEnrolled));
    return resultCode;
}

napi_value FaceTipsCodeConstructor(napi_env env)
{
    napi_value faceTipsCode = nullptr;
    napi_value faceAuthTipTooBright = nullptr;
    napi_value faceAuthTipTooDark = nullptr;
    napi_value faceAuthTipTooClose = nullptr;
    napi_value faceAuthTipTooFar = nullptr;
    napi_value faceAuthTipTooHigh = nullptr;
    napi_value faceAuthTipTooLow = nullptr;
    napi_value faceAuthTipTooRight = nullptr;
    napi_value faceAuthTipTooLeft = nullptr;
    napi_value faceAuthTipTooMuchMotion = nullptr;
    napi_value faceAuthTipPoorGaze = nullptr;
    napi_value faceAuthTipNotDetected = nullptr;
    NAPI_CALL(env, napi_create_object(env, &faceTipsCode));
    NAPI_CALL(env, napi_create_int32(env, FaceTipsCode::FACE_AUTH_TIP_TOO_BRIGHT, &faceAuthTipTooBright));
    NAPI_CALL(env, napi_create_int32(env, FaceTipsCode::FACE_AUTH_TIP_TOO_DARK, &faceAuthTipTooDark));
    NAPI_CALL(env, napi_create_int32(env, FaceTipsCode::FACE_AUTH_TIP_TOO_CLOSE, &faceAuthTipTooClose));
    NAPI_CALL(env, napi_create_int32(env, FaceTipsCode::FACE_AUTH_TIP_TOO_FAR, &faceAuthTipTooFar));
    NAPI_CALL(env, napi_create_int32(env, FaceTipsCode::FACE_AUTH_TIP_TOO_HIGH, &faceAuthTipTooHigh));
    NAPI_CALL(env, napi_create_int32(env, FaceTipsCode::FACE_AUTH_TIP_TOO_LOW, &faceAuthTipTooLow));
    NAPI_CALL(env, napi_create_int32(env, FaceTipsCode::FACE_AUTH_TIP_TOO_RIGHT, &faceAuthTipTooRight));
    NAPI_CALL(env, napi_create_int32(env, FaceTipsCode::FACE_AUTH_TIP_TOO_LEFT, &faceAuthTipTooLeft));
    NAPI_CALL(env, napi_create_int32(env, FaceTipsCode::FACE_AUTH_TIP_TOO_MUCH_MOTION, &faceAuthTipTooMuchMotion));
    NAPI_CALL(env, napi_create_int32(env, FaceTipsCode::FACE_AUTH_TIP_POOR_GAZE, &faceAuthTipPoorGaze));
    NAPI_CALL(env, napi_create_int32(env, FaceTipsCode::FACE_AUTH_TIP_NOT_DETECTED, &faceAuthTipNotDetected));
    NAPI_CALL(env, napi_set_named_property(env, faceTipsCode, "FACE_AUTH_TIP_TOO_BRIGHT", faceAuthTipTooBright));
    NAPI_CALL(env, napi_set_named_property(env, faceTipsCode, "FACE_AUTH_TIP_TOO_DARK", faceAuthTipTooDark));
    NAPI_CALL(env, napi_set_named_property(env, faceTipsCode, "FACE_AUTH_TIP_TOO_CLOSE", faceAuthTipTooClose));
    NAPI_CALL(env, napi_set_named_property(env, faceTipsCode, "FACE_AUTH_TIP_TOO_FAR", faceAuthTipTooFar));
    NAPI_CALL(env, napi_set_named_property(env, faceTipsCode, "FACE_AUTH_TIP_TOO_HIGH", faceAuthTipTooHigh));
    NAPI_CALL(env, napi_set_named_property(env, faceTipsCode, "FACE_AUTH_TIP_TOO_LOW", faceAuthTipTooLow));
    NAPI_CALL(env, napi_set_named_property(env, faceTipsCode, "FACE_AUTH_TIP_TOO_RIGHT", faceAuthTipTooRight));
    NAPI_CALL(env, napi_set_named_property(env, faceTipsCode, "FACE_AUTH_TIP_TOO_LEFT", faceAuthTipTooLeft));
    NAPI_CALL(env, napi_set_named_property(env, faceTipsCode,
        "FACE_AUTH_TIP_TOO_MUCH_MOTION", faceAuthTipTooMuchMotion));
    NAPI_CALL(env, napi_set_named_property(env, faceTipsCode, "FACE_AUTH_TIP_POOR_GAZE", faceAuthTipPoorGaze));
    NAPI_CALL(env, napi_set_named_property(env, faceTipsCode, "FACE_AUTH_TIP_NOT_DETECTED", faceAuthTipNotDetected));
    return faceTipsCode;
}

napi_value FingerprintTipsConstructorForInnerkits(napi_env env)
{
    napi_value fingerprintTips = nullptr;
    napi_value fingerprintTipGood = nullptr;
    napi_value fingerprintTipImagerDirty = nullptr;
    napi_value fingerprintTipInsufficient = nullptr;
    napi_value fingerprintTipPartial = nullptr;
    napi_value fingerprintTipTooFast = nullptr;
    napi_value fingerprintTipTooSlow = nullptr;
    NAPI_CALL(env, napi_create_object(env, &fingerprintTips));
    NAPI_CALL(env, napi_create_int32(env, FingerprintTips::FINGERPRINT_AUTH_TIP_GOOD, &fingerprintTipGood));
    NAPI_CALL(env, napi_create_int32(env, FingerprintTips::FINGERPRINT_AUTH_TIP_IMAGER_DIRTY,
        &fingerprintTipImagerDirty));
    NAPI_CALL(env, napi_create_int32(env, FingerprintTips::FINGERPRINT_AUTH_TIP_INSUFFICIENT,
        &fingerprintTipInsufficient));
    NAPI_CALL(env, napi_create_int32(env, FingerprintTips::FINGERPRINT_AUTH_TIP_PARTIAL, &fingerprintTipPartial));
    NAPI_CALL(env, napi_create_int32(env, FingerprintTips::FINGERPRINT_AUTH_TIP_TOO_FAST, &fingerprintTipTooFast));
    NAPI_CALL(env, napi_create_int32(env, FingerprintTips::FINGERPRINT_AUTH_TIP_TOO_SLOW, &fingerprintTipTooSlow));
    NAPI_CALL(env, napi_set_named_property(env, fingerprintTips, "FINGERPRINT_TIP_GOOD", fingerprintTipGood));
    NAPI_CALL(env, napi_set_named_property(env, fingerprintTips,
        "FINGERPRINT_TIP_IMAGER_DIRTY", fingerprintTipImagerDirty));
    NAPI_CALL(env, napi_set_named_property(env, fingerprintTips,
        "FINGERPRINT_TIP_INSUFFICIENT", fingerprintTipInsufficient));
    NAPI_CALL(env, napi_set_named_property(env, fingerprintTips,
        "FINGERPRINT_TIP_PARTIAL", fingerprintTipPartial));
    NAPI_CALL(env, napi_set_named_property(env, fingerprintTips,
        "FINGERPRINT_TIP_TOO_FAST", fingerprintTipTooFast));
    NAPI_CALL(env, napi_set_named_property(env, fingerprintTips,
        "FINGERPRINT_TIP_TOO_SLOW", fingerprintTipTooSlow));
    return fingerprintTips;
}

napi_value NapiAccountIAMConstant::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor descriptors[] = {
        DECLARE_NAPI_PROPERTY("AuthType", AuthTypeConstructor(env)),
        DECLARE_NAPI_PROPERTY("AuthSubType", AuthSubTypeConstructor(env)),
        DECLARE_NAPI_PROPERTY("AuthTrustLevel", AuthTrustLevelConstructor(env)),
        DECLARE_NAPI_PROPERTY("GetPropertyType", GetPropertyTypeConstructor(env)),
        DECLARE_NAPI_PROPERTY("SetPropertyType", SetPropertyTypeConstructor(env)),
        DECLARE_NAPI_PROPERTY("AuthMethod", AuthMethodConstructor(env)),
        DECLARE_NAPI_PROPERTY("Module", ModuleConstructor(env)),
        DECLARE_NAPI_PROPERTY("ResultCode", ResultCodeConstructor(env)),
        DECLARE_NAPI_PROPERTY("FaceTipsCode", FaceTipsCodeConstructor(env)),
        DECLARE_NAPI_PROPERTY("FingerprintTips", FingerprintTipsConstructorForInnerkits(env)),
    };
    napi_define_properties(env, exports, sizeof(descriptors) / sizeof(napi_property_descriptor), descriptors);
    return exports;
}
}  // namespace AccountJsKit
}  // namespace OHOS
