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

#include "json_utils.h"
#include <cinttypes>
#include <cstdint>
#include <string>
#include "securec.h"
namespace OHOS {
namespace AccountSA {
#define RECURSE_FLAG_TRUE 1
#define DECIMALISM 10

bool IsKeyExist(const CJson *jsonObj, const std::string &key)
{
    if (jsonObj == nullptr || key.empty()) {
        return false;
    }

    CJson *item = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    return item != nullptr;
}

bool IsKeyExist(const CJsonUnique &jsonObj, const std::string &key)
{
    return IsKeyExist(jsonObj.get(), key);
}

bool IsArray(const CJson *const item)
{
    return cJSON_IsArray(item) != 0;
}

bool IsArray(const CJsonUnique &item)
{
    return IsArray(item.get());
}

bool IsBool(const CJson *const item)
{
    return cJSON_IsBool(item) != 0;
}

bool IsBool(const CJsonUnique &item)
{
    return IsBool(item.get());
}

bool IsNumber(const CJson *const item)
{
    return cJSON_IsNumber(item) != 0;
}

bool IsNumber(const CJsonUnique &item)
{
    return IsNumber(item.get());
}

bool IsString(const CJson *const item)
{
    return cJSON_IsString(item) != 0;
}

bool IsString(const CJsonUnique &item)
{
    return IsString(item.get());
}

bool IsObject(const CJson *const item)
{
    return cJSON_IsObject(item) != 0;
}

bool IsObject(const CJsonUnique &item)
{
    return IsObject(item.get());
}

bool IsInvalid(const CJson *const item)
{
    return cJSON_IsInvalid(item) != 0;
}

bool IsInvalid(const CJsonUnique &item)
{
    return IsInvalid(item.get()) != 0;
}

bool IsStructured(CJson *jsonObj)
{
    return IsObject(jsonObj);
}

bool IsStructured(const CJsonUnique &jsonObj)
{
    return IsStructured(jsonObj.get());
}

void FreeJson(CJson *jsonObj)
{
    cJSON_Delete(jsonObj);
    jsonObj = nullptr;
}

CJsonUnique CreateJsonFromString(const std::string &jsonStr)
{
    if (jsonStr.empty()) {
        return nullptr;
    }
    CJsonUnique aPtr(cJSON_Parse(jsonStr.c_str()), FreeJson);
    return aPtr;
}

CJsonUnique CreateJsonNull(void)
{
    CJsonUnique aPtr(cJSON_CreateNull(), FreeJson);
    return aPtr;
}

CJsonUnique CreateJson(void)
{
    CJsonUnique aPtr(cJSON_CreateObject(), FreeJson);
    return aPtr;
}

CJsonUnique CreateJsonArray(void)
{
    CJsonUnique aPtr(cJSON_CreateArray(), FreeJson);
    return aPtr;
}

int DeleteItemFromJson(CJson *jsonObj, const std::string &key)
{
    if (!IsKeyExist(jsonObj, key)) {
        return 0;
    }
    cJSON_DeleteItemFromObjectCaseSensitive(jsonObj, key.c_str());
    return 1;
}

int DeleteItemFromJson(CJsonUnique &jsonObj, const std::string &key)
{
    return DeleteItemFromJson(jsonObj.get(), key);
}

void FreeJsonString(char *jsonStr)
{
    if (jsonStr != nullptr) {
        cJSON_free(jsonStr);
    }
}

std::string PackJsonToString(const CJson *jsonObj)
{
    char *buf = cJSON_PrintUnformatted(jsonObj);
    if (buf == nullptr) {
        return std::string();
    }
    std::string bufStr = std::string(buf);
    FreeJsonString(buf);
    return bufStr;
}

std::string PackJsonToString(const CJsonUnique &jsonObj)
{
    return PackJsonToString(jsonObj.get());
}

int32_t GetItemNum(const CJson *jsonObj)
{
    return cJSON_GetArraySize(jsonObj);
}

int32_t GetItemNum(const CJsonUnique &jsonObj)
{
    return cJSON_GetArraySize(jsonObj.get());
}

bool GetObjFromJson(const CJson *jsonObj, const std::string &key, CJson **value)
{
    if (jsonObj == nullptr || key.empty()) {
        return false;
    }

    *value = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    return IsObject(*value);
}

CJson *GetObjFromJson(const CJson *jsonObj, const std::string &key)
{
    CJson *value = nullptr;
    GetObjFromJson(jsonObj, key, &value);
    return value;
}

CJson *GetObjFromJson(const CJsonUnique &jsonObj, const std::string &key)
{
    return GetObjFromJson(jsonObj.get(), key);
}

CJson *GetItemFromArray(const CJson *jsonArr, int32_t index)
{
    return cJSON_GetArrayItem(jsonArr, index);
}

CJson *GetItemFromArray(const CJsonUnique &jsonArr, int32_t index)
{
    return GetItemFromArray(jsonArr.get(), index);
}

bool GetStringFromJson(const CJson *jsonObj, const std::string &key, std::string &value)
{
    if (jsonObj == nullptr || key.empty()) {
        return false;
    }
    CJson *item = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    if (IsString(item)) {
        value = cJSON_GetStringValue(item);
        return true;
    }
    return false;
}

std::string GetStringFromJson(const CJson *jsonObj, const std::string &key)
{
    std::string value;
    GetStringFromJson(jsonObj, key, value);
    return value;
}

std::string GetStringFromJson(const CJsonUnique &jsonObj, const std::string &key)
{
    return GetStringFromJson(jsonObj.get(), key);
}

CJsonUnique CreateJsonFromMap(const std::map<std::string, std::string> &mapData)
{
    CJson *jsonObj = cJSON_CreateObject();

    for (const auto &pair : mapData) {
        cJSON_AddStringToObject(jsonObj, pair.first.c_str(), pair.second.c_str());
    }

    CJsonUnique aPtr(jsonObj, FreeJson);
    return aPtr;
}

std::map<std::string, std::string> PackJsonToMap(const CJson *jsonObj)
{
    if (!IsObject(jsonObj)) {
        return {};
    }

    std::map<std::string, std::string> mapData;
    for (cJSON *item = jsonObj->child; item != nullptr; item = item->next) {
        if (item->valuestring != nullptr) {
            mapData[item->string] = item->valuestring;
        }
    }
    return mapData;
}

std::map<std::string, std::string> PackJsonToMap(const CJsonUnique &jsonObj)
{
    return PackJsonToMap(jsonObj.get());
}

bool GetVectorStringFromJson(const CJson *jsonObj, const std::string &key, std::vector<std::string> &value)
{
    if (!IsKeyExist(jsonObj, key)) {
        return false;
    }
    CJson *array = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    if (!IsArray(array)) {
        return false;
    }

    int32_t arraySize = cJSON_GetArraySize(array);
    for (int32_t i = 0; i < arraySize; i++) {
        CJson *item = cJSON_GetArrayItem(array, i);
        if (item->type == cJSON_String) {
            value.push_back(item->valuestring);
        }
    }
    return true;
}

std::vector<std::string> GetVectorStringFromJson(const CJson *jsonObj, const std::string &key)
{
    std::vector<std::string> value;
    GetVectorStringFromJson(jsonObj, key, value);
    return value;
}

std::vector<std::string> GetVectorStringFromJson(const CJsonUnique &jsonObj, const std::string &key)
{
    return GetVectorStringFromJson(jsonObj.get(), key);
}

std::vector<uint8_t> GetVectorUint8FromJson(const CJson *jsonObj, const std::string &key)
{
    if (!IsKeyExist(jsonObj, key)) {
        return {};
    }
    std::vector<uint8_t> result;
    CJson *array = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    if (!IsArray(array)) {
        return result;
    }

    int32_t arraySize = cJSON_GetArraySize(array);
    for (int32_t i = 0; i < arraySize; i++) {
        CJson *item = cJSON_GetArrayItem(array, i);
        if (item->type == cJSON_Number) {
            result.push_back(item->valueint);
        }
    }
    return result;
}

std::vector<uint8_t> GetVectorUint8FromJson(const CJsonUnique &jsonObj, const std::string &key)
{
    return GetVectorUint8FromJson(jsonObj.get(), key);
}

CJson *GetItemFromJson(const CJson *const object, const std::string &key)
{
    if (!IsKeyExist(object, key)) {
        return nullptr;
    }
    return cJSON_GetObjectItemCaseSensitive(object, key.c_str());
}

CJson *GetItemFromJson(CJsonUnique &object, const std::string &key)
{
    return GetItemFromJson(object.get(), key);
}

bool AddSetStringToJson(CJson *jsonObj, const std::string &key, const std::set<std::string> &setData)
{
    if (jsonObj == nullptr || key.empty()) {
        return false;
    }

    CJson *array = cJSON_CreateArray();
    for (const std::string &item : setData) {
        cJSON_AddItemToArray(array, cJSON_CreateString(item.c_str()));
    }
    CJson *item = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    if (item == nullptr) {
        if (!cJSON_AddItemToObject(jsonObj, key.c_str(), array)) {
            cJSON_Delete(array);
            return false;
        }
    } else {
        if (!cJSON_ReplaceItemInObjectCaseSensitive(jsonObj, key.c_str(), array)) {
            cJSON_Delete(array);
            return false;
        }
    }
    return true;
}

bool AddSetStringToJson(CJsonUnique &jsonObj, const std::string &key, const std::set<std::string> &setData)
{
    return AddSetStringToJson(jsonObj.get(), key, setData);
}

bool GetSetStringFromJson(const CJson *jsonObj, const std::string &key, std::set<std::string> &setData)
{
    if (jsonObj == nullptr || key.empty()) {
        return false;
    }
    CJson *arrayItem = cJSON_GetObjectItem(jsonObj, key.c_str());
    if (!IsArray(arrayItem)) {
        return false;
    }
    int32_t arraySize = cJSON_GetArraySize(arrayItem);
    for (int32_t i = 0; i < arraySize; ++i) {
        CJson *element = cJSON_GetArrayItem(arrayItem, i);
        if (IsString(element)) {
            setData.insert(element->valuestring);
        }
    }
    return true;
}

bool GetSetStringFromJson(const CJsonUnique &jsonObj, const std::string &key, std::set<std::string> &setData)
{
    return GetSetStringFromJson(jsonObj.get(), key, setData);
}

bool AddVectorStringToJson(CJson *jsonObj, const std::string &key, const std::vector<std::string> &vec)
{
    if (jsonObj == nullptr || key.empty()) {
        return false;
    }

    CJson *array = cJSON_CreateArray();
    for (const auto &str : vec) {
        AddStringToArray(array, str.c_str());
    }
    CJson *item = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    if (item == nullptr) {
        if (!cJSON_AddItemToObject(jsonObj, key.c_str(), array)) {
            cJSON_Delete(array);
            return false;
        }
    } else {
        if (!cJSON_ReplaceItemInObjectCaseSensitive(jsonObj, key.c_str(), array)) {
            cJSON_Delete(array);
            return false;
        }
    }
    return true;
}

bool AddVectorStringToJson(CJsonUnique &jsonObj, const std::string &key, const std::vector<std::string> &vec)
{
    return AddVectorStringToJson(jsonObj.get(), key, vec);
}

bool GetIntFromJson(const CJson *jsonObj, const std::string &key, int32_t &value)
{
    if (jsonObj == nullptr || key.empty()) {
        return false;
    }

    CJson *item = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    if (IsNumber(item)) {
        value = static_cast<int32_t>(cJSON_GetNumberValue(item));
        return true;
    } else if (IsString(item)) {
        std::string str = cJSON_GetStringValue(item);
        if (str.empty()) {
            return false;
        }
        value = static_cast<int32_t>(strtoull(str.c_str(), nullptr, DECIMALISM));
        return true;
    }
    return false;
}

bool GetIntFromJson(const CJsonUnique &jsonObj, const std::string &key, int32_t &value)
{
    return GetIntFromJson(jsonObj.get(), key, value);
}

int32_t GetIntFromJson(const CJson *jsonObj, const std::string &key)
{
    int32_t value = 0;
    if (!IsKeyExist(jsonObj, key)) {
        return 0;
    }
    GetIntFromJson(jsonObj, key, value);
    return value;
}

int32_t GetIntFromJson(const CJsonUnique &jsonObj, const std::string &key)
{
    return GetIntFromJson(jsonObj.get(), key);
}

bool GetUint64FromJson(const CJson *jsonObj, const std::string &key, uint64_t &value)
{
    if (!IsKeyExist(jsonObj, key)) {
        return false;
    }
    CJson *item = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    if (item == nullptr) {
        return false;
    }
    if (IsString(item)) {
        std::string str = cJSON_GetStringValue(item);
        if (str.empty()) {
            return false;
        }
        value = strtoull(str.c_str(), nullptr, DECIMALISM);
        return true;
    } else if (IsNumber(item)) {
        value = static_cast<uint64_t>(cJSON_GetNumberValue(item));
        return true;
    }

    return false;
}

uint64_t GetUint64FromJson(const CJson *jsonObj, const std::string &key)
{
    uint64_t value;
    GetUint64FromJson(jsonObj, key, value);
    return value;
}

uint64_t GetUint64FromJson(const CJsonUnique &jsonObj, const std::string &key)
{
    return GetUint64FromJson(jsonObj.get(), key);
}

bool GetInt64FromJson(const CJson *jsonObj, const std::string &key, int64_t &value)
{
    if (!IsKeyExist(jsonObj, key)) {
        return false;
    }
    CJson *item = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    if (item == nullptr) {
        return false;
    }
    if (IsString(item)) {
        std::string str = cJSON_GetStringValue(item);
        ;
        if (str.empty()) {
            return false;
        }
        value = static_cast<int64_t>(strtoull(str.c_str(), nullptr, DECIMALISM));
        return true;
    } else if (IsNumber(item)) {
        value = static_cast<int64_t>(cJSON_GetNumberValue(item));
        return true;
    }

    return false;
}

int64_t GetInt64FromJson(const CJson *jsonObj, const std::string &key)
{
    int64_t value;
    GetInt64FromJson(jsonObj, key, value);
    return value;
}

int64_t GetInt64FromJson(const CJsonUnique &jsonObj, const std::string &key)
{
    return GetInt64FromJson(jsonObj.get(), key);
}

bool GetBoolFromJson(const CJson *jsonObj, const std::string &key, bool &value)
{
    if (jsonObj == nullptr || key.empty()) {
        return false;
    }

    CJson *item = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    if (IsBool(item)) {
        value = cJSON_IsTrue(item) != 0;
        return true;
    }
    return false;
}

bool GetBoolFromJson(const CJsonUnique &jsonObj, const std::string &key, bool &value)
{
    return GetBoolFromJson(jsonObj.get(), key, value);
}

bool GetBoolFromJson(const CJson *jsonObj, const std::string &key)
{
    bool value = false;
    GetBoolFromJson(jsonObj, key, value);
    return value;
}

bool GetBoolFromJson(const CJsonUnique &jsonObj, const std::string &key)
{
    return GetBoolFromJson(jsonObj.get(), key);
}

bool AddObjToJson(CJson *jsonObj, const std::string &key, const CJson *childObj)
{
    if (jsonObj == nullptr || key.empty() || childObj == nullptr) {
        return false;
    }

    CJson *tmpObj = cJSON_Duplicate(childObj, RECURSE_FLAG_TRUE);
    if (tmpObj == nullptr) {
        return false;
    }

    CJson *item = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    if (item == nullptr) {
        if (!cJSON_AddItemToObject(jsonObj, key.c_str(), tmpObj)) {
            cJSON_Delete(tmpObj);
            return false;
        }
    } else {
        if (!cJSON_ReplaceItemInObjectCaseSensitive(jsonObj, key.c_str(), tmpObj)) {
            cJSON_Delete(tmpObj);
            return false;
        }
    }
    return true;
}

bool AddObjToJson(CJsonUnique &jsonObj, const std::string &key, CJsonUnique &childObj)
{
    return AddObjToJson(jsonObj.get(), key, childObj.get());
}

bool AddVectorUint8ToJson(CJson *jsonObj, const std::string &key, std::vector<uint8_t> arr)
{
    if (jsonObj == nullptr || key.empty()) {
        return false;
    }
    CJson *array = cJSON_CreateArray();
    for (size_t i = 0; i < arr.size(); i++) {
        cJSON_AddItemToArray(array, cJSON_CreateNumber(arr[i]));
    }

    CJson *tmpObj = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    if (tmpObj == nullptr) {
        if (!cJSON_AddItemToObject(jsonObj, key.c_str(), array)) {
            cJSON_Delete(array);
            return false;
        }
    } else {
        if (!cJSON_ReplaceItemInObjectCaseSensitive(jsonObj, key.c_str(), array)) {
            cJSON_Delete(array);
            return false;
        }
    }
    return true;
}

bool AddVectorUint8ToJson(CJsonUnique &jsonObj, const std::string &key, std::vector<uint8_t> arr)
{
    return AddVectorUint8ToJson(jsonObj.get(), key, arr);
}

bool AddObjToArray(CJson *jsonArr, CJson *item)
{
    if (!IsArray(jsonArr) || item == nullptr) {
        return false;
    }

    CJson *tmpObj = cJSON_Duplicate(item, RECURSE_FLAG_TRUE);
    if (tmpObj == nullptr) {
        return false;
    }
    if (!cJSON_AddItemToArray(jsonArr, tmpObj)) {
        cJSON_Delete(tmpObj);
        return false;
    }
    return true;
}

bool AddObjToArray(CJsonUnique &jsonArr, CJsonUnique &item)
{
    return AddObjToArray(jsonArr.get(), item.get());
}

bool AddStringToArray(CJson *jsonArr, const char *string)
{
    if (!IsArray(jsonArr) || string == nullptr) {
        return false;
    }

    CJson *strObj = cJSON_CreateString(string);
    if (strObj == nullptr) {
        return false;
    }
    if (!cJSON_AddItemToArray(jsonArr, strObj)) {
        cJSON_Delete(strObj);
        return false;
    }
    return true;
}

bool AddStringToArray(CJsonUnique &jsonArr, const char *string)
{
    return AddStringToArray(jsonArr.get(), string);
}

bool AddStringToJson(CJson *jsonObj, const std::string &key, const std::string &value)
{
    if (jsonObj == nullptr || key.empty()) {
        return false;
    }

    CJson *tmpObj = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    if (tmpObj == nullptr) {
        if (cJSON_AddStringToObject(jsonObj, key.c_str(), value.c_str()) == nullptr) {
            return false;
        }
    } else {
        CJson *tmp = cJSON_CreateString(value.c_str());
        if (tmp == nullptr) {
            return false;
        }
        if (!cJSON_ReplaceItemInObjectCaseSensitive(jsonObj, key.c_str(), tmp)) {
            cJSON_Delete(tmp);
            return false;
        }
    }

    return true;
}

bool AddStringToJson(CJsonUnique &jsonObj, const std::string &key, const std::string &value)
{
    return AddStringToJson(jsonObj.get(), key, value);
}

bool AddBoolToJson(CJson *jsonObj, const std::string &key, const bool value)
{
    if (jsonObj == nullptr || key.empty()) {
        return false;
    }

    CJson *tmpObj = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    if (tmpObj == nullptr) {
        if (cJSON_AddBoolToObject(jsonObj, key.c_str(), value) == nullptr) {
            return false;
        }
    } else {
        CJson *tmp = cJSON_CreateBool(value);
        if (tmp == nullptr) {
            return false;
        }
        if (!cJSON_ReplaceItemInObjectCaseSensitive(jsonObj, key.c_str(), tmp)) {
            cJSON_Delete(tmp);
            return false;
        }
    }

    return true;
}

bool AddBoolToJson(CJsonUnique &jsonObj, const std::string &key, const bool value)
{
    return AddBoolToJson(jsonObj.get(), key, value);
}

bool AddIntToJson(CJson *jsonObj, const std::string &key, const int value)
{
    if (jsonObj == nullptr || key.empty()) {
        return false;
    }

    CJson *tmpObj = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    if (tmpObj == nullptr) {
        if (cJSON_AddNumberToObject(jsonObj, key.c_str(), value) == nullptr) {
            return false;
        }
    } else {
        CJson *tmp = cJSON_CreateNumber(value);
        if (tmp == nullptr) {
            return false;
        }
        if (!cJSON_ReplaceItemInObjectCaseSensitive(jsonObj, key.c_str(), tmp)) {
            cJSON_Delete(tmp);
            return false;
        }
    }

    return true;
}

bool AddIntToJson(CJsonUnique &jsonObj, const std::string &key, const int value)
{
    return AddIntToJson(jsonObj.get(), key, value);
}

bool AddUint64ToJson(CJson *jsonObj, const std::string &key, uint64_t value)
{
    if (jsonObj == nullptr || key.empty()) {
        return false;
    }
    char buffer[65] = {0};
    if (sprintf_s(buffer, sizeof(buffer), "%" PRIu64, value) <= 0) {
        return false;
    }

    return AddStringToJson(jsonObj, key, buffer);
}

bool AddUint64ToJson(CJsonUnique &jsonObj, const std::string &key, uint64_t value)
{
    return AddUint64ToJson(jsonObj.get(), key, value);
}

bool AddInt64ToJson(CJson *jsonObj, const std::string &key, int64_t value)
{
    if (jsonObj == nullptr || key.empty()) {
        return false;
    }
    char buffer[65] = {0};
    if (sprintf_s(buffer, sizeof(buffer), "%" PRIu64, value) <= 0) {
        return false;
    }

    return AddStringToJson(jsonObj, key, buffer);
}

bool AddInt64ToJson(CJsonUnique &jsonObj, const std::string &key, int64_t value)
{
    return AddInt64ToJson(jsonObj.get(), key, value);
}

CJsonUnique CreateCJsonString(const char *string)
{
    cJSON *rawPtr = cJSON_CreateString(string);
    CJsonUnique uniquePtr(rawPtr, FreeJson);
    return uniquePtr;
}

double GetJsonNumberValue(const CJsonUnique &item)
{
    return GetJsonNumberValue(item.get());
}

double GetJsonNumberValue(cJSON *item)
{
    if (item == nullptr) {
        return static_cast<double>(0);
    }
    return cJSON_GetNumberValue(item);
}

CJson *GetJsonArrayFromJson(const CJson *jsonObj, const std::string &key)
{
    if (jsonObj == nullptr || key.empty()) {
        return nullptr;
    }
    CJson *item = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    if (IsArray(item)) {
        return item;
    }
    return nullptr;
}
} // namespace AccountSA
} // namespace OHOS
