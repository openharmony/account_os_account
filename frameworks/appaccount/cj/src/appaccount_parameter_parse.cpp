/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License")
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

#include "appaccount_parameter_parse.h"

#include <cinttypes>
#include "array_wrapper.h"
#include "bool_wrapper.h"
#include "double_wrapper.h"
#include "int_wrapper.h"
#include "long_wrapper.h"
#include "securec.h"
#include "string_wrapper.h"
#include "want_params_wrapper.h"
#include "appaccount_ffi.h"

namespace OHOS::AccountSA {
const char *FD = "FD";
const char *TYPE_PROPERTY = "type";
const char *VALUE_PROPERTY = "value";
const int8_t I32_TYPE = 0;
const int8_t DOUBLE_TYPE = 1;
const int8_t STR_TYPE = 2;
const int8_t BOOL_TYPE = 3;
const int8_t FD_TYPE = 4;
const int8_t STR_PTR_TYPE = 5;
const int8_t I32_PTR_TYPE = 6;
const int8_t I64_PTR_TYPE = 7;
const int8_t BOOL_PTR_TYPE = 8;
const int8_t DOUBLE_PTR_TYPE = 9;
const int8_t FD_PTR_TYPE = 10;
const int32_t NONE_VALUE = 1;
const int8_t NO_ERROR = 0;
const int8_t ERR_CES_FAILED = 1;
const int8_t ERR_NO_MEMORY = -2;
using Want = OHOS::AAFwk::Want;
using WantParams = OHOS::AAFwk::WantParams;

void charPtrToVector(char **charPtr, int size, std::vector<std::string> &result)
{
    for (int i = 0; i < size; i++) {
        result.push_back(std::string(charPtr[i]));
    }
}

void SetFdData(std::string key, int *value, WantParams &wantP)
{
    WantParams wp;
    wp.SetParam(TYPE_PROPERTY, OHOS::AAFwk::String::Box(FD));
    wp.SetParam(VALUE_PROPERTY, OHOS::AAFwk::Integer::Box(*value));
    sptr<OHOS::AAFwk::IWantParams> pWantParams = OHOS::AAFwk::WantParamWrapper::Box(wp);
    wantP.SetParam(key, pWantParams);
}

bool InnerSetWantParamsArrayString(
    const std::string &key, const std::vector<std::string> &value, AAFwk::WantParams &wantParams)
{
    size_t size = value.size();
    sptr<AAFwk::IArray> ao = new (std::nothrow) AAFwk::Array(size, AAFwk::g_IID_IString);
    if (ao != nullptr) {
        for (size_t i = 0; i < size; i++) {
            ao->Set(i, AAFwk::String::Box(value[i]));
        }
        wantParams.SetParam(key, ao);
        return true;
    } else {
        return false;
    }
}

bool InnerSetWantParamsArrayInt(const std::string &key, const std::vector<int> &value,
    AAFwk::WantParams &wantParams)
{
    size_t size = value.size();
    sptr<AAFwk::IArray> ao = new (std::nothrow) AAFwk::Array(size, AAFwk::g_IID_IInteger);
    if (ao != nullptr) {
        for (size_t i = 0; i < size; i++) {
            ao->Set(i, AAFwk::Integer::Box(value[i]));
        }
        wantParams.SetParam(key, ao);
        return true;
    } else {
        return false;
    }
}

bool InnerSetWantParamsArrayLong(const std::string &key, const std::vector<long> &value,
    AAFwk::WantParams &wantParams)
{
    size_t size = value.size();
    sptr<AAFwk::IArray> ao = new (std::nothrow) AAFwk::Array(size, AAFwk::g_IID_ILong);
    if (ao != nullptr) {
        for (size_t i = 0; i < size; i++) {
            ao->Set(i, AAFwk::Long::Box(value[i]));
        }
        wantParams.SetParam(key, ao);
        return true;
    } else {
        return false;
    }
}

bool InnerSetWantParamsArrayBool(const std::string &key, const std::vector<bool> &value,
    AAFwk::WantParams &wantParams)
{
    size_t size = value.size();
    sptr<AAFwk::IArray> ao = new (std::nothrow) AAFwk::Array(size, AAFwk::g_IID_IBoolean);
    if (ao != nullptr) {
        for (size_t i = 0; i < size; i++) {
            ao->Set(i, AAFwk::Boolean::Box(value[i]));
        }
        wantParams.SetParam(key, ao);
        return true;
    } else {
        return false;
    }
}

bool InnerSetWantParamsArrayDouble(
    const std::string &key, const std::vector<double> &value, AAFwk::WantParams &wantParams)
{
    size_t size = value.size();
    sptr<AAFwk::IArray> ao = new (std::nothrow) AAFwk::Array(size, AAFwk::g_IID_IDouble);
    if (ao != nullptr) {
        for (size_t i = 0; i < size; i++) {
            ao->Set(i, AAFwk::Double::Box(value[i]));
        }
        wantParams.SetParam(key, ao);
        return true;
    } else {
        return false;
    }
}

void InnerSetWantParamsArrayFD(CParameters* head, int64_t size, AAFwk::WantParams &wantParams)
{
    sptr<AAFwk::IArray> ao = new (std::nothrow) AAFwk::Array(size, AAFwk::g_IID_IWantParams);
    if (ao != nullptr) {
        for (size_t i = 0; i < static_cast<size_t>(size); i++) {
            WantParams wp;
            SetFdData(std::string(head->key), static_cast<int *>(head->value) + i, wp);
            wp.DumpInfo(0);
            ao->Set(i, OHOS::AAFwk::WantParamWrapper::Box(wp));
        }
        wantParams.SetParam(std::string(head->key), ao);
    }
    return;
}

void SetDataParameters(CArrParameters parameters, WantParams &wantP)
{
    for (int i = 0; i < parameters.size; i++) {
        auto head = parameters.head + i;
        auto key = std::string(head->key);
        if (head->valueType == I32_TYPE) { // int32_t
            wantP.SetParam(key, OHOS::AAFwk::Integer::Box(*static_cast<int32_t *>(head->value)));
        } else if (head->valueType == DOUBLE_TYPE) { // double
            wantP.SetParam(key, OHOS::AAFwk::Double::Box(*static_cast<double *>(head->value)));
        } else if (head->valueType == STR_TYPE) { // std::string
            wantP.SetParam(key, OHOS::AAFwk::String::Box(std::string(static_cast<char *>(head->value))));
        } else if (head->valueType == BOOL_TYPE) { // bool
            wantP.SetParam(key, OHOS::AAFwk::Boolean::Box(*static_cast<bool *>(head->value)));
        } else if (head->valueType == FD_TYPE) { // "FD"
            SetFdData(key, static_cast<int *>(head->value), wantP);
        } else if (head->valueType == STR_PTR_TYPE) { // char**
            char **strPtr = static_cast<char **>(head->value);
            std::vector<std::string> strVec;
            charPtrToVector(strPtr, head->size, strVec);
            InnerSetWantParamsArrayString(key, strVec, wantP);
        } else if (head->valueType == I32_PTR_TYPE) { // int32_t*
            int *intArr = static_cast<int *>(head->value);
            std::vector<int> intVec(intArr, intArr + head->size);
            InnerSetWantParamsArrayInt(key, intVec, wantP);
        } else if (head->valueType == I64_PTR_TYPE) { // int64_t*
            long *longArr = static_cast<long *>(head->value);
            std::vector<long> longVec(longArr, longArr + head->size);
            InnerSetWantParamsArrayLong(key, longVec, wantP);
        } else if (head->valueType == BOOL_PTR_TYPE) { // bool*
            bool *boolArr = static_cast<bool *>(head->value);
            std::vector<bool> boolVec(boolArr, boolArr + head->size);
            InnerSetWantParamsArrayBool(key, boolVec, wantP);
        } else if (head->valueType == DOUBLE_PTR_TYPE) { // double*
            double *doubleArr = static_cast<double *>(head->value);
            std::vector<double> doubleVec(doubleArr, doubleArr + head->size);
            InnerSetWantParamsArrayDouble(key, doubleVec, wantP);
        } else if (head->valueType == FD_PTR_TYPE) { // FD*
            InnerSetWantParamsArrayFD(head, head->size, wantP);
        }
    }
}

char *MallocCString(const std::string &origin)
{
    if (origin.empty()) {
        return nullptr;
    }
    auto len = origin.length() + 1;
    char *res = static_cast<char *>(malloc(sizeof(char) * len));
    if (res == nullptr) {
        return nullptr;
    }
    return std::char_traits<char>::copy(res, origin.c_str(), len);
}

char *MallocCString(const std::string &origin, int32_t &code)
{
    if (origin.empty() || code != NO_ERROR) {
        return nullptr;
    }
    auto len = origin.length() + 1;
    char *res = static_cast<char *>(malloc(sizeof(char) * len));
    if (res == nullptr) {
        code = ERR_NO_MEMORY;
        return nullptr;
    }
    return std::char_traits<char>::copy(res, origin.c_str(), len);
}

int32_t InnerWrapWantParamsString(WantParams &wantParams, CParameters *p)
{
    auto value = wantParams.GetParam(p->key);
    AAFwk::IString *ao = AAFwk::IString::Query(value);
    if (ao == nullptr) {
        return NONE_VALUE;
    }
    std::string natValue = OHOS::AAFwk::String::Unbox(ao);
    p->value = MallocCString(natValue);
    p->size = static_cast<int64_t>(natValue.length()) + 1;
    p->valueType = STR_TYPE;
    return NO_ERROR;
}

template <class TBase, class T, class NativeT>
int32_t InnerWrapWantParamsT(WantParams &wantParams, CParameters *p)
{
    auto value = wantParams.GetParam(p->key);
    TBase *ao = TBase::Query(value);
    if (ao == nullptr) {
        return NONE_VALUE;
    }
    NativeT natValue = T::Unbox(ao);
    NativeT *ptr = static_cast<NativeT *>(malloc(sizeof(NativeT)));
    if (ptr == nullptr) {
        return ERR_NO_MEMORY;
    }
    *ptr = natValue;
    p->value = static_cast<void*>(ptr);
    p->size = sizeof(NativeT);
    return NO_ERROR;
}

int32_t InnerWrapWantParamsArrayString(sptr<AAFwk::IArray> &ao, CParameters *p)
{
    long size = 0;
    if (ao->GetLength(size) != ERR_OK) {
        return ERR_CES_FAILED;
    }
    if (size == 0) {
        return ERR_CES_FAILED;
    }
    char **arrP = static_cast<char **>(malloc(sizeof(char *) * size));
    if (arrP == nullptr) {
        return ERR_NO_MEMORY;
    }
    for (long i = 0; i < size; i++) {
        sptr<AAFwk::IInterface> iface = nullptr;
        if (ao->Get(i, iface) == ERR_OK) {
            AAFwk::IString *iValue = AAFwk::IString::Query(iface);
            if (iValue != nullptr) {
                auto val = AAFwk::String::Unbox(iValue);
                arrP[i] = MallocCString(val);
            }
        }
    }
    p->size = size;
    p->value = static_cast<void *>(arrP);
    return NO_ERROR;
}

void ClearParametersPtr(CParameters **ptr, int count, bool isKey)
{
    CParameters *p = *ptr;
    for (int i = 0; i < count; i++) {
        free(p[i].key);
        free(p[i].value);
        p[i].key = nullptr;
        p[i].value = nullptr;
    }
    if (!isKey) {
        free(p[count].key);
        p[count].key = nullptr;
    }
    free(*ptr);
    *ptr = nullptr;
}

template <class TBase, class T, class NativeT>
int32_t InnerWrapWantParamsArrayT(sptr<AAFwk::IArray> &ao, CParameters *p)
{
    long size = 0;
    if (ao->GetLength(size) != ERR_OK) {
        return ERR_CES_FAILED;
    }
    if (size == 0) {
        return ERR_CES_FAILED;
    }
    NativeT *arrP = static_cast<NativeT *>(malloc(sizeof(NativeT) * size));
    if (arrP == nullptr) {
        return ERR_NO_MEMORY;
    }
    for (long i = 0; i < size; i++) {
        sptr<AAFwk::IInterface> iface = nullptr;
        if (ao->Get(i, iface) == ERR_OK) {
            TBase *iValue = TBase::Query(iface);
            if (iValue != nullptr) {
                arrP[i] = T::Unbox(iValue);
            }
        }
    }
    p->size = size;
    p->value = static_cast<void *>(arrP);
    return NO_ERROR;
}

int32_t GetFDValue(WantParams &wantParams, std::string key, int *ptr)
{
    auto value = wantParams.GetParam(key);
    AAFwk::IWantParams *o = AAFwk::IWantParams::Query(value);
    if (o == nullptr) {
        return NONE_VALUE;
    }
    AAFwk::WantParams wp = AAFwk::WantParamWrapper::Unbox(o);
    value = wp.GetParam(VALUE_PROPERTY);
    AAFwk::IInteger *ao = AAFwk::IInteger::Query(value);
    if (ao == nullptr) {
        return NONE_VALUE;
    }
    *ptr = OHOS::AAFwk::Integer::Unbox(ao);
    return NO_ERROR;
}

int32_t InnerWrapWantParamsFd(WantParams &wantParams, CParameters *p)
{
    int *ptr = static_cast<int *>(malloc(sizeof(int)));
    if (ptr == nullptr) {
        return ERR_NO_MEMORY;
    }
    int error = GetFDValue(wantParams, std::string(p->key), ptr);
    if (error != NO_ERROR) {
        free(ptr);
        return error;
    }
    p->value = static_cast<void*>(ptr);
    p->size = sizeof(int32_t);
    p->valueType = FD_TYPE;
    return NO_ERROR;
}

int32_t InnerWrapWantParamsArrayFd(sptr<AAFwk::IArray> &ao, CParameters *p)
{
    long size = 0;
    if (ao->GetLength(size) != ERR_OK) {
        return ERR_CES_FAILED;
    }
    if (size == 0) {
        return ERR_CES_FAILED;
    }
    int *arrP = static_cast<int *>(malloc(sizeof(int) * size));
    if (arrP == nullptr) {
        return ERR_NO_MEMORY;
    }
    for (long i = 0; i < size; i++) {
        sptr<AAFwk::IInterface> iface = nullptr;
        if (ao->Get(i, iface) == ERR_OK) {
            AAFwk::IWantParams *iValue = AAFwk::IWantParams::Query(iface);
            if (iValue == nullptr) {
                free(arrP);
                return ERR_CES_FAILED;
            }
            WantParams wantP = AAFwk::WantParamWrapper::Unbox(iValue);
            int ret = GetFDValue(wantP, std::string(p->key), arrP + i);
            if (ret != NO_ERROR) {
                free(arrP);
                return ret;
            }
        }
    }
    p->size = size;
    p->value = arrP;
    p->valueType = FD_PTR_TYPE;
    return NO_ERROR;
}

int32_t InnerWrapWantParamsArray(WantParams &wantParams, sptr<AAFwk::IArray> &ao, CParameters *p)
{
    if (AAFwk::Array::IsStringArray(ao)) {
        p->valueType = STR_PTR_TYPE;
        return InnerWrapWantParamsArrayString(ao, p);
    } else if (AAFwk::Array::IsBooleanArray(ao)) {
        p->valueType = BOOL_PTR_TYPE;
        return InnerWrapWantParamsArrayT<AAFwk::IBoolean, AAFwk::Boolean, bool>(ao, p);
    } else if (AAFwk::Array::IsIntegerArray(ao)) {
        p->valueType = I32_PTR_TYPE;
        return InnerWrapWantParamsArrayT<AAFwk::IInteger, AAFwk::Integer, int>(ao, p);
    } else if (AAFwk::Array::IsLongArray(ao)) {
        p->valueType = I64_PTR_TYPE;
        return InnerWrapWantParamsArrayT<AAFwk::ILong, AAFwk::Long, int64_t>(ao, p);
    } else if (AAFwk::Array::IsDoubleArray(ao)) {
        p->valueType = DOUBLE_PTR_TYPE;
        return InnerWrapWantParamsArrayT<AAFwk::IDouble, AAFwk::Double, double>(ao, p);
    } else {
        p->valueType = FD_PTR_TYPE;
        return InnerWrapWantParamsArrayFd(ao, p);
    }
}
} // namespace::OHOS::AccountSA