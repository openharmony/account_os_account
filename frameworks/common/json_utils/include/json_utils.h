/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OS_ACCOUNT_JSON_UTILS_H
#define OS_ACCOUNT_JSON_UTILS_H

#include <map>
#include <memory>
#include <vector>
#include <string>
#include <set>
#include <functional>
#include "cJSON.h"

namespace OHOS {
namespace AccountSA {
typedef cJSON CJson;
typedef std::unique_ptr<CJson, std::function<void(CJson *ptr)>> CJsonUnique;

/* No need to call FreeJson to free the returned pointer when it's no longer in use. */
CJsonUnique CreateJsonFromString(const std::string &jsonStr);
CJsonUnique CreateJsonNull(void);
CJsonUnique CreateJson(void);
CJsonUnique CreateJsonArray(void);
CJsonUnique CreateCJsonString(const char *string);

int DeleteItemFromJson(CJson *jsonObj, const std::string &key);
int DeleteItemFromJson(CJsonUnique &jsonObj, const std::string &key);

/* No need to call FreeJsonString to free the returned pointer when it's no longer in use. */
std::string PackJsonToString(const CJsonUnique &jsonObj);
std::string PackJsonToString(const CJson *jsonObj);

int32_t GetItemNum(const CJson *jsonObj);
int32_t GetItemNum(const CJsonUnique &jsonObj);

/*
 * Can't release the returned pointer, otherwise, an exception may occur.
 * It refers to the parent object(param--jsonObj)'s memory.
 * It will be recycled along with jsonObj when jsonObj is released.
 */
bool GetObjFromJson(const CJson *jsonObj, const std::string &key, CJson **value);
CJson *GetObjFromJson(const CJson *jsonObj, const std::string &key);
CJson *GetObjFromJson(const CJsonUnique &jsonObj, const std::string &key);
CJson *GetItemFromJson(const CJson *const object, const std::string &key);
CJson *GetItemFromJson(CJsonUnique &object, const std::string &key);
CJson *GetItemFromArray(const CJson *jsonArr, int32_t index);
CJson *GetItemFromArray(const CJsonUnique &jsonArr, int32_t index);

// common
bool IsKeyExist(const CJson *json_obj, const std::string &key);
bool IsKeyExist(const CJsonUnique &json_obj, const std::string &key);
bool IsStructured(CJson *jsonObj);
bool IsStructured(const CJsonUnique &jsonObj);
bool IsArray(const CJson *item);
bool IsArray(const CJsonUnique &item);
bool IsBool(const CJson *item);
bool IsBool(const CJsonUnique &item);
bool IsNumber(const CJson *item);
bool IsNumber(const CJsonUnique &item);
bool IsString(const CJson *item);
bool IsString(const CJsonUnique &item);
bool IsObject(const CJson *item);
bool IsObject(const CJsonUnique &item);
bool IsInvalid(const CJson *item);
bool IsInvalid(const CJsonUnique &item);

// bool
bool GetBoolFromJson(const CJsonUnique &jsonObj, const std::string &key, bool &value);
bool GetBoolFromJson(const CJson *jsonObj, const std::string &key, bool &value);
bool GetBoolFromJson(const CJsonUnique &jsonObj, const std::string &key);
bool GetBoolFromJson(const CJson *jsonObj, const std::string &key);
bool AddBoolToJson(CJson *jsonObj, const std::string &key, const bool value);
bool AddBoolToJson(CJsonUnique &jsonObj, const std::string &key, const bool value);

// int32
bool GetIntFromJson(const CJson *jsonObj, const std::string &key, int32_t &value);
int32_t GetIntFromJson(const CJson *jsonObj, const std::string &key);
int32_t GetIntFromJson(const CJsonUnique &jsonObj, const std::string &key);
bool AddIntToJson(CJson *jsonObj, const std::string &key, const int value);
bool AddIntToJson(CJsonUnique &jsonObj, const std::string &key, const int value);

// int64
bool GetInt64FromJson(const CJson *jsonObj, const std::string &key, int64_t &value);
int64_t GetInt64FromJson(const CJson *jsonObj, const std::string &key);
int64_t GetInt64FromJson(const CJsonUnique &jsonObj, const std::string &key);
bool AddInt64ToJson(CJson *jsonObj, const std::string &key, int64_t value);
bool AddInt64ToJson(CJsonUnique &jsonObj, const std::string &key, int64_t value);

// uint64
bool GetUint64FromJson(const CJson *jsonObj, const std::string &key, uint64_t &value);
uint64_t GetUint64FromJson(const CJson *jsonObj, const std::string &key);
uint64_t GetUint64FromJson(const CJsonUnique &jsonObj, const std::string &key);
bool AddUint64ToJson(CJson *jsonObj, const std::string &key, uint64_t value);
bool AddUint64ToJson(CJsonUnique &jsonObj, const std::string &key, uint64_t value);

// double
double GetJsonNumberValue(const CJsonUnique &item);
double GetJsonNumberValue(cJSON *item);

// string
bool GetStringFromJson(const CJson *jsonObj, const std::string &key, std::string &value);
std::string GetStringFromJson(const CJson *jsonObj, const std::string &key);
std::string GetStringFromJson(const CJsonUnique &jsonObj, const std::string &key);
bool AddStringToJson(CJson *jsonObj, const std::string &key, const std::string &value);
bool AddStringToJson(CJsonUnique &jsonObj, const std::string &key, const std::string &value);
bool AddStringToArray(CJson *jsonArr, const char *string);
bool AddStringToArray(CJsonUnique &jsonArr, const char *string);

CJson *GetJsonArrayFromJson(const CJson *jsonObj, const std::string &key);

// string vector
bool GetVectorStringFromJson(const CJson *jsonObj, const std::string &key, std::vector<std::string> &value);
std::vector<std::string> GetVectorStringFromJson(const CJson *jsonObj, const std::string &key);
std::vector<std::string> GetVectorStringFromJson(const CJsonUnique &jsonObj, const std::string &key);
bool AddVectorStringToJson(CJson *jsonObj, const std::string &key, const std::vector<std::string> &vec);
bool AddVectorStringToJson(CJsonUnique &jsonObj, const std::string &key, const std::vector<std::string> &vec);

// uint8 vector
std::vector<uint8_t> GetVectorUint8FromJson(const CJson *jsonObj, const std::string &key);
std::vector<uint8_t> GetVectorUint8FromJson(const CJsonUnique &jsonObj, const std::string &key);
bool AddVectorUint8ToJson(CJsonUnique &jsonObj, const std::string &key, std::vector<uint8_t> arr);
bool AddVectorUint8ToJson(CJson *jsonObj, const std::string &key, std::vector<uint8_t> arr);

// map
std::map<std::string, std::string> PackJsonToMap(const CJson *jsonObj);
std::map<std::string, std::string> PackJsonToMap(const CJsonUnique &jsonObj);
CJsonUnique CreateJsonFromMap(const std::map<std::string, std::string> &mapData);

// set
bool GetSetStringFromJson(const CJsonUnique &jsonObj, const std::string &key, std::set<std::string> &setData);
bool GetSetStringFromJson(const CJson *jsonObj, const std::string &key, std::set<std::string> &setData);
bool AddSetStringToJson(CJsonUnique &jsonObj, const std::string &key, const std::set<std::string> &setData);

// add obj
bool AddObjToJson(CJson *jsonObj, const std::string &key, const CJson *childObj);
bool AddObjToJson(CJsonUnique &jsonObj, const std::string &key, CJsonUnique &childObj);
bool AddObjToArray(CJsonUnique &jsonArr, CJsonUnique &item);

template <typename>
constexpr bool dependent_false = false;

template <typename T, typename dataType>
bool GetDataByType(const CJson *jsonObject, const std::string &key, dataType &data)
{
    static_assert(std::is_same_v<T, int> || std::is_same_v<T, int32_t> || std::is_same_v<T, uint32_t> ||
        std::is_same_v<T, int64_t> || std::is_same_v<T, uint64_t> || std::is_same_v<T, bool> ||
        std::is_same_v<T, std::string> || std::is_same_v<T, cJSON *> || std::is_enum_v<T> ||
        std::is_same_v<T, std::vector<std::string>> || std::is_same_v<T, std::set<std::string>>,
        "Unsupported type for GetDataByType");

    if constexpr (std::is_same_v<T, int> || std::is_same_v<T, int32_t>) {
        return GetIntFromJson(jsonObject, key, data);
    } else if constexpr (std::is_same_v<T, int64_t>) {
        return GetInt64FromJson(jsonObject, key, data);
    } else if constexpr (std::is_same_v<T, uint64_t>) {
        return GetUint64FromJson(jsonObject, key, data);
    } else if constexpr (std::is_same_v<T, bool>) {
        return GetBoolFromJson(jsonObject, key, data);
    } else if constexpr (std::is_same_v<T, std::string>) {
        return GetStringFromJson(jsonObject, key, data);
    } else if constexpr (std::is_same_v<T, cJSON *>) {
        return GetObjFromJson(jsonObject, key, &data);
    } else if constexpr (std::is_same_v<T, std::vector<std::string>>) {
        return GetVectorStringFromJson(jsonObject, key, data);
    } else if constexpr (std::is_same_v<T, std::set<std::string>>) {
        return GetSetStringFromJson(jsonObject, key, data);
    } else if constexpr (std::is_enum_v<T> || std::is_same_v<T, uint32_t>) {
        int value = 0;
        if (!GetIntFromJson(jsonObject, key, value)) {
            return false;
        }
        data = static_cast<dataType>(value);
        return true;
    } else {
        static_assert(dependent_false<T>, "Non-exhaustive handling of types");
    }
}

template <typename T, typename dataType>
bool GetDataByType(const CJsonUnique &jsonObject, const std::string &key, dataType &data)
{
    return GetDataByType<T, dataType>(jsonObject.get(), key, data);
}
} // namespace AccountSA
} // namespace OHOS
#endif // OS_ACCOUNT_JSON_UTILS_H
