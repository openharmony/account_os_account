/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <gtest/gtest.h>

#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "json_utils.h"

using namespace OHOS;
using namespace testing::ext;
using namespace OHOS::AccountSA;

typedef enum {
    LOGOUT = 0,
    LOGIN_BACKGROUND,
    LOGIN,
    LOG_END,
} TestLoginStatus;

class JsonUtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();

    void SetUp();
    void TearDown();
};

void JsonUtilsTest::SetUpTestCase() {}
void JsonUtilsTest::TearDownTestCase() {}
void JsonUtilsTest::SetUp() {}
void JsonUtilsTest::TearDown() {}

/*
 * @tc.name: CreateJsonFromStringTest001
 * @tc.desc: CreateJsonFromString
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, CreateJsonFromStringTest001, TestSize.Level4)
{
    std::string test;
    EXPECT_EQ(nullptr, CreateJsonFromString(test));
}

/*
 * @tc.name: CreateJsonFromStringTest002
 * @tc.desc: CreateJsonFromString
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, CreateJsonFromStringTest002, TestSize.Level4)
{
    const std::string stringJson = "{\"key1\":\"value1\",\"key2\":\"value2\"}";
    auto json = CreateJsonFromString(stringJson);
    EXPECT_EQ(GetStringFromJson(json, "key1"), "value1");
    EXPECT_EQ(GetStringFromJson(json, "key2"), "value2");
    std::string value;
    EXPECT_TRUE(GetDataByType<std::string>(json.get(), "key2", value));
    EXPECT_EQ(value, "value2");
}

/*
 * @tc.name: CreateJsonTest001
 * @tc.desc: CreateJson
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, CreateJsonTest001, TestSize.Level4)
{
    auto json = CreateJson();
    EXPECT_TRUE(AddStringToJson(json, "key1", "value1"));
    EXPECT_TRUE(AddStringToJson(json, "key2", "value2"));
    EXPECT_EQ(GetStringFromJson(json, "key1"), "value1");
    EXPECT_EQ(GetStringFromJson(json, "key2"), "value2");
}

/*
 * @tc.name: CreateJsonArrayTest001
 * @tc.desc: CreateJsonArray
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, CreateJsonArrayTest001, TestSize.Level4)
{
    auto jsonArray = CreateJsonArray();
    const std::string stringJson1 = "{\"key1\":\"value1\",\"key2\":\"value2\"}";
    const std::string stringJson2 = "{\"key1\":\"value1\",\"key2\":\"value2\"}";
    auto json1 = CreateJsonFromString(stringJson1);
    auto json2 = CreateJsonFromString(stringJson2);
    EXPECT_EQ(AddObjToArray(jsonArray, json1), true);
    EXPECT_EQ(AddObjToArray(jsonArray, json2), true);
    EXPECT_EQ(GetStringFromJson(GetItemFromArray(jsonArray, 0), "key1"), "value1");
    EXPECT_EQ(GetStringFromJson(GetItemFromArray(jsonArray, 1), "key2"), "value2");
}

/*
 * @tc.name: PackJsonToStringTest001
 * @tc.desc: PackJsonToString
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, PackJsonToStringTest001, TestSize.Level4)
{
    std::string res = PackJsonToString(nullptr);
    EXPECT_TRUE(res.empty());
}

/*
 * @tc.name: PackJsonToStringTest002
 * @tc.desc: PackJsonToString
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, PackJsonToStringTest002, TestSize.Level4)
{
    const std::string stringJson = "{\"key1\":\"value1\",\"key2\":\"value2\"}";
    auto json = CreateJsonFromString(stringJson);
    std::string res = PackJsonToString(json);
    EXPECT_EQ(stringJson, res);
}

/*
 * @tc.name: GetItemNumTest001
 * @tc.desc: GetItemNum
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, GetItemNumTest001, TestSize.Level4)
{
    const std::string stringJson = "{\"key1\":\"value1\",\"key2\":\"value2\"}";
    auto json1 = CreateJsonFromString(stringJson);
    auto json2 = CreateJsonFromString(stringJson);
    auto jsonArray = CreateJsonArray();
    EXPECT_TRUE(AddObjToArray(jsonArray, json1));
    EXPECT_TRUE(AddObjToArray(jsonArray, json2));

    int arraySize = GetItemNum(jsonArray);
    EXPECT_EQ(2, arraySize);
}

/*
 * @tc.name: GetMapFromJsonTest001
 * @tc.desc: PackJsonToMap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, GetMapFromJsonTest001, TestSize.Level4)
{
    map<string, string> result = PackJsonToMap(nullptr);
    EXPECT_TRUE(result.empty());
}

/*
 * @tc.name: GetMapFromJsonTest002
 * @tc.desc: PackJsonToMap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, GetMapFromJsonTest002, TestSize.Level4)
{
    auto emptyJson = CreateJson();
    map<string, string> result = PackJsonToMap(emptyJson.get());
    EXPECT_TRUE(result.empty());
}

/*
 * @tc.name: GetMapFromJsonTest003
 * @tc.desc: PackJsonToMap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, GetMapFromJsonTest003, TestSize.Level4)
{
    std::map<std::string, std::string> mapDate = {{"key1", "value1"}, {"key2", "value2"}};
    auto jsonObj = CreateJsonFromMap(mapDate);
    EXPECT_EQ(PackJsonToMap(jsonObj), mapDate);
}

/*
 * @tc.name: IsKeyExistTest001
 * @tc.desc: IsKeyExist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, IsKeyExistTest001, TestSize.Level4)
{
    EXPECT_FALSE(IsKeyExist(nullptr, "11111"));
}

/*
 * @tc.name: IsKeyExistTest002
 * @tc.desc: IsKeyExist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, IsKeyExistTest002, TestSize.Level4)
{
    auto jsonObj = CreateJson();
    EXPECT_FALSE(IsKeyExist(jsonObj, ""));
}

/*
 * @tc.name: IsKeyExistTest003
 * @tc.desc: IsKeyExist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, IsKeyExistTest003, TestSize.Level4)
{
    auto jsonObj = CreateJson();
    ASSERT_TRUE(AddStringToJson(jsonObj, "nested_key", "nested_value"));
    EXPECT_TRUE(IsKeyExist(jsonObj, "nested_key"));
    EXPECT_FALSE(IsKeyExist(jsonObj, "nested_key1"));
}

/*
 * @tc.name: IsStructuredTest001
 * @tc.desc: IsStructured
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, IsStructuredTest001, TestSize.Level4)
{
    auto jsonObj = CreateJson();
    EXPECT_FALSE(IsStructured(nullptr));
    ASSERT_TRUE(AddStringToJson(jsonObj, "nested_key", "nested_value"));
    EXPECT_TRUE(IsStructured(jsonObj.get()));
}

/*
 * @tc.name: DeleteItemFromJsonTest001
 * @tc.desc: DeleteItemFromJson
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, DeleteItemFromJsonTest001, TestSize.Level4)
{
    auto jsonObj = CreateJson();
    AddStringToJson(jsonObj, "key1", "nested_value");
    EXPECT_TRUE(DeleteItemFromJson(jsonObj, "key1"));
    EXPECT_FALSE(IsKeyExist(jsonObj, "key1"));
}

/*
 * @tc.name: GetObjFromJsonTest001
 * @tc.desc: AddObjToJson, GetObjFromJson
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, GetObjFromJsonTest001, TestSize.Level4)
{
    std::string test;
    std::string retString;
    EXPECT_EQ(nullptr, GetObjFromJson(nullptr, test));

    auto json = CreateJson();
    auto jsonObj = CreateJson();
    AddStringToJson(jsonObj, "nested_key", "nested_value");
    EXPECT_TRUE(AddObjToJson(json, "key1", jsonObj));
    cJSON *item = GetObjFromJson(json, "key1");
    retString = GetStringFromJson(item, "nested_key");
    EXPECT_EQ("nested_value", retString);
}

/*
 * @tc.name: GetItemFromArray001
 * @tc.desc: GetItemFromArray
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, GetItemFromArray001, TestSize.Level4)
{
    std::string searchKey = "test1";
    auto jsonArray = CreateJsonArray();
    ASSERT_TRUE(AddStringToArray(jsonArray, "test1"));
    ASSERT_TRUE(AddStringToArray(jsonArray, "test2"));
    ASSERT_TRUE(AddStringToArray(jsonArray, "test3"));
    cJSON *item = GetItemFromArray(jsonArray, 1);

    if (IsString(item)) {
        std::string retStr = item->valuestring;
        EXPECT_EQ("test2", retStr);
    }
    item = GetItemFromArray(jsonArray, 2);
    if (IsString(item)) {
        std::string retStr = item->valuestring;
        EXPECT_EQ("test3", retStr);
    }
}

/*
 * @tc.name: GetStringFromJsonTest001
 * @tc.desc: AddStringToJson, GetStringFromJson
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, GetStringFromJsonTest001, TestSize.Level4)
{
    std::string test;
    std::string res;
    auto jsonObj = CreateJson();
    AddStringToJson(jsonObj, "test0", "0");
    AddStringToJson(jsonObj, "test1", "1");
    AddStringToJson(jsonObj, "test2", "2");
    std::string resValue1 = GetStringFromJson(jsonObj.get(), "test0");
    EXPECT_EQ("0", resValue1);

    std::string resValue2 = GetStringFromJson(jsonObj.get(), "test1");
    EXPECT_EQ("1", resValue2);
}

/*
 * @tc.name: AddObjToJsonTest001
 * @tc.desc: AddStringToJson
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, AddObjToJsonTest001, TestSize.Level4)
{
    EXPECT_FALSE(AddObjToJson(nullptr, "", nullptr));
    auto jsonObj = CreateJson();
    EXPECT_TRUE(AddStringToJson(jsonObj, "key1", "0"));
    ASSERT_EQ("0", GetStringFromJson(jsonObj, "key1"));
    EXPECT_TRUE(AddStringToJson(jsonObj, "key2", "1"));
    ASSERT_EQ("1", GetStringFromJson(jsonObj, "key2"));
}

/*
 * @tc.name: AddObjToArrayTest001
 * @tc.desc: AddObjToArray
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(JsonUtilsTest, AddObjToArrayTest001, TestSize.Level3)
{
    CJsonUnique nullPtr = nullptr;
    CJsonUnique jsonArray = CreateJsonArray();
    CJsonUnique jsonInner = CreateJson();
    CJsonUnique jsonObj = CreateJson();
    EXPECT_FALSE(AddObjToArray(jsonArray, nullPtr));
    EXPECT_FALSE(AddObjToArray(jsonObj, jsonInner));
}

/*
 * @tc.name: AddObjToArrayTest002
 * @tc.desc: AddObjToArray
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, AddObjToArrayTest002, TestSize.Level4)
{
    auto jsonArray = CreateJsonArray();
    auto anotherObj = CreateJson();
    AddStringToJson(anotherObj, "test1", "1");
    EXPECT_TRUE(AddObjToArray(jsonArray, anotherObj));
    cJSON *item = GetItemFromArray(jsonArray, 0);
    std::string retValue = GetStringFromJson(item, "test1");
    EXPECT_EQ("1", retValue);
}

/*
 * @tc.name: AddInt64ToJsonTest001
 * @tc.desc: AddInt64ToJson
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, AddInt64ToJsonTest001, TestSize.Level4)
{
    std::string key = "test_key";
    int64_t value = 1234567890;
    EXPECT_FALSE(AddInt64ToJson(nullptr, key, value));

    auto jsonObj = CreateJson();
    EXPECT_TRUE(AddInt64ToJson(jsonObj, key, value));
    int64_t retrievedValue;
    EXPECT_TRUE(GetInt64FromJson(jsonObj.get(), key, retrievedValue));
    EXPECT_EQ(retrievedValue, value);

    int64_t maxValue = INT64_MAX;
    EXPECT_TRUE(AddInt64ToJson(jsonObj, "max_key", maxValue));
    GetInt64FromJson(jsonObj.get(), "max_key", retrievedValue);
    EXPECT_EQ(retrievedValue, maxValue);

    int64_t minValue = INT64_MIN;
    EXPECT_TRUE(AddInt64ToJson(jsonObj, "min_key", minValue));
    GetInt64FromJson(jsonObj.get(), "min_key", retrievedValue);
    EXPECT_TRUE(retrievedValue);
    EXPECT_EQ(retrievedValue, minValue);

    EXPECT_FALSE(AddInt64ToJson(jsonObj, "", value));
}

/*
 * @tc.name: GetVectorStringFromJson001
 * @tc.desc: GetVectorStringFromJson
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, GetVectorStringFromJson001, TestSize.Level4)
{
    auto jsonArray = CreateJsonArray();
    auto result = GetVectorStringFromJson(jsonArray, "string_array");
    ASSERT_TRUE(result.empty());
}

/*
 * @tc.name: GetVectorStringFromJson002
 * @tc.desc: GetVectorStringFromJson
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, GetVectorStringFromJson002, TestSize.Level4)
{
    auto jsonArray = CreateJson();
    std::vector<std::string> testVec{"first", "second", "third"};
    EXPECT_TRUE(AddVectorStringToJson(jsonArray, "string_array", testVec));

    auto result = GetVectorStringFromJson(jsonArray, "string_array");
    ASSERT_EQ(3, result.size());
    EXPECT_EQ("first", result[0]);
    EXPECT_EQ("second", result[1]);
    EXPECT_EQ("third", result[2]);
}

/*
 * @tc.name: GetVectorUint8FromJson001
 * @tc.desc: AddVectorUint8ToJson, GetVectorUint8FromJson
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, GetVectorUint8FromJson001, TestSize.Level4)
{
    auto jsonObj = CreateJson();
    auto result = GetVectorUint8FromJson(jsonObj, "KeyNoExist");
    EXPECT_EQ(0, result.size());
    std::vector<uint8_t> uintString = {1, 2, 3, 4, 5};
    CJsonUnique nullJson;
    EXPECT_FALSE(AddVectorUint8ToJson(nullJson, "Key1", uintString));
    EXPECT_FALSE(AddVectorUint8ToJson(jsonObj, "", uintString));
    AddVectorUint8ToJson(jsonObj, "basic_array", uintString);
    result = GetVectorUint8FromJson(jsonObj, "basic_array");
    ASSERT_EQ(5, result.size());
    EXPECT_EQ(static_cast<uint8_t>(1), result[0]);
    EXPECT_EQ(static_cast<uint8_t>(2), result[1]);
    EXPECT_EQ(static_cast<uint8_t>(3), result[2]);
}

/*
 * @tc.name: GetObjectItemTest001
 * @tc.desc: AddObjToJson, GetItemFromJson
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, GetObjectItemTest001, TestSize.Level4)
{
    auto jsonObj = CreateJson();
    EXPECT_EQ(GetItemFromJson(jsonObj, "keyNoExist"), nullptr);
    const std::string stringJson = "{\"key1\":\"value1\",\"key2\":\"value2\"}";
    auto jsonString = CreateJsonFromString(stringJson);
    EXPECT_TRUE(AddObjToJson(jsonObj, "key", jsonString));
    auto jsonRes = GetItemFromJson(jsonObj, "key");
    EXPECT_TRUE(IsObject(jsonRes));
    EXPECT_EQ("value1", GetStringFromJson(jsonRes, "key1"));
}

/*
 * @tc.name: IsArray001
 * @tc.desc: IsArray
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, IsArray001, TestSize.Level4)
{
    auto jsonArray = CreateJsonArray();
    ASSERT_TRUE(AddStringToArray(jsonArray, "first"));
    ASSERT_TRUE(AddStringToArray(jsonArray, "second"));
    ASSERT_TRUE(AddStringToArray(jsonArray, "third"));
    bool isArrayResult = IsArray(jsonArray);
    EXPECT_TRUE(isArrayResult);
}

/*
 * @tc.name: IsBool001
 * @tc.desc: IsBool
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, IsBool001, TestSize.Level4)
{
    auto jsonObj = CreateJson();
    EXPECT_TRUE(AddBoolToJson(jsonObj, "test1", true));
    bool isBoolResult = IsBool(GetItemFromJson(jsonObj, "test1"));
    EXPECT_TRUE(isBoolResult);
}

/*
 * @tc.name: IsNumber001
 * @tc.desc: IsNumber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, IsNumber001, TestSize.Level4)
{
    auto jsonObj = CreateJson();
    EXPECT_TRUE(AddIntToJson(jsonObj, "test0", 0));
    bool isNumberResult = IsNumber(GetItemFromJson(jsonObj, "test0"));
    EXPECT_TRUE(isNumberResult);
}

/*
 * @tc.name: IsString001
 * @tc.desc: IsString
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, IsString001, TestSize.Level4)
{
    auto jsonObj = CreateJson();
    EXPECT_TRUE(AddStringToJson(jsonObj, "test0", "0"));
    bool isStringResult = IsString(GetItemFromJson(jsonObj, "test0"));
    EXPECT_TRUE(isStringResult);
}

/*
 * @tc.name: IsObject001
 * @tc.desc: IsObject
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, IsObject001, TestSize.Level4)
{
    auto jsonObj = CreateJson();
    auto nestedObj = CreateJson();
    ASSERT_TRUE(AddObjToJson(jsonObj, "test1", nestedObj));
    bool isObjectResult = IsObject(GetItemFromJson(jsonObj, "test1"));
    EXPECT_TRUE(isObjectResult);
}

/*
 * @tc.name: IsInvalid001
 * @tc.desc: IsInvalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, IsInvalid001, TestSize.Level4)
{
    auto jsonObj = CreateJson();
    ASSERT_TRUE(AddStringToJson(jsonObj, "test0", "0"));
    bool isInvalidResult = IsInvalid(jsonObj);
    EXPECT_FALSE(isInvalidResult);
}

/*
 * @tc.name: AddVectorStringToJson001
 * @tc.desc: AddVectorStringToJson
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, AddVectorStringToJson001, TestSize.Level4)
{
    auto jsonObj = CreateJson();
    std::vector<std::string> value = {"apple", "banana", "cherry"};
    auto result = AddVectorStringToJson(jsonObj, "", value);
    EXPECT_FALSE(result);
}

/*
 * @tc.name: AddVectorStringToJson002
 * @tc.desc: AddVectorStringToJson
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, AddVectorStringToJson002, TestSize.Level4)
{
    auto jsonObj = CreateJson();
    std::vector<std::string> value = {"apple", "banana", "cherry"};
    auto result = AddVectorStringToJson(jsonObj, "key", value);
    EXPECT_TRUE(result);
    std::vector<std::string> resVec = GetVectorStringFromJson(jsonObj, "key");
    for (int i = 0; i < value.size(); i++) {
        EXPECT_EQ(value[i], resVec[i]);
    }
}

/*
 * @tc.name: AddStringToJsonTest001
 * @tc.desc: AddStringToJson
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, AddStringToJsonTest001, TestSize.Level4)
{
    auto jsonObj = CreateJson();
    EXPECT_FALSE(AddStringToJson(jsonObj, "", "test0"));
    EXPECT_TRUE(AddStringToJson(jsonObj, "test0", ""));

    auto jsonObjct = CreateJson();
    EXPECT_TRUE(AddStringToJson(jsonObjct, "test0", "value0"));
    std::string retStr = GetStringFromJson(jsonObjct, "test0");
    EXPECT_EQ("value0", retStr);
}

/*
 * @tc.name: Uint64StringToJsonTest001
 * @tc.desc: AddUint64ToJson, GetUint64FromJson
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, Uint64StringToJsonTest001, TestSize.Level3)
{
    auto jsonObj = CreateJson();
    std::string key = "test_key";
    uint64_t value = 18446744073709551615ull;

    EXPECT_FALSE(AddUint64ToJson(jsonObj, "", -1));
    bool result = AddUint64ToJson(jsonObj, key, value);
    EXPECT_TRUE(result);

    uint64_t value64 = 0;
    GetUint64FromJson(jsonObj.get(), key, value64);
    EXPECT_EQ(value, value64);
}

/*
 * @tc.name: Uint64StringToJsonTest002
 * @tc.desc: AddUint64ToJson, GetUint64FromJson from string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, Uint64StringToJsonTest002, TestSize.Level3)
{
    auto jsonObj = CreateJson();
    std::string key = "test_key";
    int value = 1234567;
    std::string strValue = "1234567";
    
    EXPECT_TRUE(AddStringToJson(jsonObj, key, strValue));
    uint64_t value64 = 0;
    GetUint64FromJson(jsonObj.get(), key, value64);
    EXPECT_EQ(value, value64);
    int64_t retInt = 0;
    GetInt64FromJson(jsonObj.get(), key, retInt);
    EXPECT_EQ(value, retInt);
}

/*
 * @tc.name: Uint64StringToJsonTest003
 * @tc.desc: AddUint64ToJson, GetUint64FromJson
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, Uint64StringToJsonTest003, TestSize.Level4)
{
    auto jsonObj = CreateJson();
    std::string key = "key";
    uint64_t value = 123;

    bool result = AddUint64ToJson(jsonObj, key, value);
    EXPECT_TRUE(result);
    uint64_t value64 = 0;
    GetUint64FromJson(jsonObj.get(), key, value64);
    EXPECT_EQ(value, value64);
}

/*
 * @tc.name: Uint64StringToJsonTest004
 * @tc.desc: AddUint64ToJson, GetUint64FromJson
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, Uint64StringToJsonTest004, TestSize.Level4)
{
    auto jsonObj = CreateJson();
    std::string key = "max_key";
    uint64_t value = UINT64_MAX;

    bool result = AddUint64ToJson(jsonObj, key, value);
    EXPECT_TRUE(result);

    uint64_t value64 = 0;
    GetUint64FromJson(jsonObj.get(), key, value64);
    EXPECT_EQ(value, value64);
}

/*
 * @tc.name: Uint64StringToJsonTest005
 * @tc.desc: AddUint64ToJson, GetUint64FromJson
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, Uint64StringToJsonTest005, TestSize.Level4)
{
    auto jsonObj = CreateJson();
    std::string key = "existing_key";
    AddStringToJson(jsonObj, key, "old_value");

    uint64_t value = 42;
    bool result = AddUint64ToJson(jsonObj, key, value);
    EXPECT_TRUE(result);

    uint64_t value64 = 0;
    GetUint64FromJson(jsonObj.get(), key, value64);
    EXPECT_EQ(value, value64);
}

/*
 * @tc.name: Uint64StringToJsonTest006
 * @tc.desc: AddUint64ToJson, GetUint64FromJson
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, Uint64StringToJsonTest006, TestSize.Level4)
{
    auto jsonObj = CreateJson();
    std::string key = "zero_key";
    uint64_t value = 0;

    bool result = AddUint64ToJson(jsonObj, key, value);
    EXPECT_TRUE(result);
    uint64_t value64 = 1;
    GetUint64FromJson(jsonObj.get(), key, value64);
    EXPECT_EQ(value, value64);
}

/*
 * @tc.name: GetIntFromJsonTest001
 * @tc.desc: GetIntFromJson
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, GetIntFromJsonTest001, TestSize.Level4)
{
    auto jsonObj = CreateJson();
    EXPECT_TRUE(AddIntToJson(jsonObj, "test0", 1));
    int32_t res = 0;
    GetIntFromJson(jsonObj.get(), "test0", res);
    EXPECT_EQ(1, res);
}

/*
 * @tc.name: AddIntToJsonTest001
 * @tc.desc: AddIntToJson, GetIntFromJson
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, AddIntToJsonTest001, TestSize.Level4)
{
    auto jsonObj = CreateJson();
    EXPECT_FALSE(AddIntToJson(jsonObj, "", 11));
    EXPECT_TRUE(AddIntToJson(jsonObj, "test0", 123));
    int32_t retValue = 0;
    GetIntFromJson(jsonObj.get(), "test0", retValue);
    EXPECT_EQ(123, retValue);
}

/*
 * @tc.name: GetBoolFromJsonTest001
 * @tc.desc: AddBoolToJson, GetBoolFromJson
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, GetBoolFromJsonTest001, TestSize.Level4)
{
    bool res;
    auto jsonObj = CreateJson();
    EXPECT_FALSE(GetBoolFromJson(jsonObj, "", res));
    EXPECT_TRUE(AddBoolToJson(jsonObj, "test0", true));
    bool retValue;
    GetBoolFromJson(jsonObj, "test0", retValue);
    EXPECT_TRUE(retValue);
}

/*
 * @tc.name: GetJsonNumberValueTest001
 * @tc.desc: GetJsonNumberValue
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, GetJsonNumberValueTest001, TestSize.Level4)
{
    auto jsonObj = CreateJson();
    ASSERT_NE(jsonObj, nullptr);
    bool addResult = AddIntToJson(jsonObj, "testKey", 4);
    ASSERT_TRUE(addResult);

    CJson *item = GetItemFromJson(jsonObj, "testKey");
    ASSERT_NE(item, nullptr);

    double result = GetJsonNumberValue(item);
    EXPECT_EQ(result, 4.0);
}

/*
 * @tc.name: AddSetStringToJsonTest001
 * @tc.desc: AddSetStringToJsonTest, GetSetStringFromJson
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, AddSetStringToJsonTest001, TestSize.Level4)
{
    auto json = CreateJson();

    std::set<std::string> list1 = {"A"};
    std::set<std::string> list2 = {"B"};
    CJsonUnique nullJson;
    EXPECT_FALSE(AddSetStringToJson(nullJson, "Key1", list1));
    EXPECT_FALSE(AddSetStringToJson(json, "", list1));
    EXPECT_TRUE(AddSetStringToJson(json, "Key1", list1));
    EXPECT_TRUE(AddSetStringToJson(json, "key2", list2));

    std::set<std::string> ResList1;
    std::set<std::string> ResList2;
    EXPECT_TRUE(GetSetStringFromJson(json, "Key1", ResList1));
    EXPECT_TRUE(GetSetStringFromJson(json, "key2", ResList2));

    EXPECT_EQ(ResList1, list1);
    EXPECT_EQ(ResList2, list2);
}

/*
 * @tc.name: GetSetStringFromJson001
 * @tc.desc: GetSetFromJson
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, GetSetStringFromJson001, TestSize.Level4)
{
    auto jsonObj = CreateJson();
    std::string key = "testKey";
    std::set<std::string> value = {"apple", "banana", "cherry"};
    AddSetStringToJson(jsonObj, key, value);
    std::set<std::string> retValue;
    CJsonUnique nullJson;
    EXPECT_FALSE(GetSetStringFromJson(nullJson, "Key1", retValue));
    GetSetStringFromJson(jsonObj, "", retValue);
    GetSetStringFromJson(jsonObj, key, retValue);
    EXPECT_EQ(value, retValue);
}

/*
 * @tc.name: CreateJsonNullTest001
 * @tc.desc: CreateJsonNull
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, CreateJsonNullTest001, TestSize.Level4)
{
    auto jsonObj = CreateJsonNull();
    EXPECT_TRUE(cJSON_IsNull(jsonObj.get()));
}

/*
 * @tc.name: GetDataByTypeTest001
 * @tc.desc: GetDataByType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, GetDataByTypeTest001, TestSize.Level4)
{
    auto jsonObj = CreateJson();
    std::string jsonNullValue;
    std::set<std::string> setValue = {"apple", "banana", "cherry"};
    std::set<std::string> retValue;
    std::string strValue = "hello";
    std::string retStrValue;
    std::vector<std::string> vectorValue = {"apple", "banana", "cherry"};
    std::vector<std::string> retVectorValue;
    bool isVerified = true;
    bool retBool;
    int64_t int64Value = 123456789;
    int64_t retInt64Value;
    int32_t int32Value = 3456789;
    int32_t retInt32Value;
    TestLoginStatus type = LOGIN;
    TestLoginStatus retType = LOGOUT;
    auto json = CreateJson();
    AddStringToJson(json, "key3", "value3");
    AddStringToJson(json, "key4", "value4");
    CJson *typeJson = nullptr;

    AddSetStringToJson(jsonObj, "set_key", setValue);
    AddStringToJson(jsonObj, "string_key", strValue);
    AddVectorStringToJson(jsonObj, "vector_key", vectorValue);
    AddBoolToJson(jsonObj, "bool_key", isVerified);
    AddInt64ToJson(jsonObj, "int64_key", int64Value);
    AddIntToJson(jsonObj, "int32_key", int32Value);
    AddIntToJson(jsonObj, "enum_key", static_cast<int32_t>(type));
    AddObjToJson(jsonObj, "cjson_key", json);

    EXPECT_FALSE(GetDataByType<std::string>(nullptr, "Key1", jsonNullValue));

    EXPECT_TRUE(GetDataByType<std::set<std::string>>(jsonObj.get(), "set_key", retValue));
    EXPECT_EQ(setValue, retValue);
    EXPECT_TRUE(GetDataByType<std::string>(jsonObj.get(), "string_key", retStrValue));
    EXPECT_EQ(strValue, retStrValue);
    EXPECT_TRUE(GetDataByType<std::vector<std::string>>(jsonObj.get(), "vector_key", retVectorValue));
    EXPECT_EQ(vectorValue, retVectorValue);
    EXPECT_TRUE(GetDataByType<bool>(jsonObj.get(), "bool_key", retBool));
    EXPECT_EQ(isVerified, retBool);
    EXPECT_TRUE(GetDataByType<int64_t>(jsonObj.get(), "int64_key", retInt64Value));
    EXPECT_EQ(int64Value, retInt64Value);
    EXPECT_TRUE(GetDataByType<int32_t>(jsonObj.get(), "int32_key", retInt32Value));
    EXPECT_EQ(int32Value, retInt32Value);
    EXPECT_TRUE(GetDataByType<TestLoginStatus>(jsonObj.get(), "enum_key", retType));
    EXPECT_EQ(type, retType);
    EXPECT_TRUE(GetDataByType<CJson *>(jsonObj.get(), "cjson_key", typeJson));
    EXPECT_EQ("value3", GetStringFromJson(typeJson, "key3"));
    EXPECT_EQ("value4", GetStringFromJson(typeJson, "key4"));
}

/*
 * @tc.name: CreateJsonStringTest001
 * @tc.desc: CreateJsonString
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, CreateJsonStringTest001, TestSize.Level4)
{
    const char *testString = "test";
    auto jsonObj = CreateJsonString(testString);
    EXPECT_EQ(*testString, *cJSON_GetStringValue(jsonObj.get()));
}

/*
 * @tc.name: GetJsonArrayFromJsonTest001
 * @tc.desc: GetJsonArrayFromJson
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, GetJsonArrayFromJsonTest001, TestSize.Level4)
{
    auto jsonObj = CreateJson();
    auto jsonAarray = CreateJsonArray();
    EXPECT_TRUE(AddStringToArray(jsonAarray, "test1"));
    EXPECT_TRUE(AddStringToArray(jsonAarray, "test2"));
    AddObjToJson(jsonObj, "key", jsonAarray);

    EXPECT_FALSE(GetJsonArrayFromJson(nullptr, "Key1"));
    EXPECT_FALSE(GetJsonArrayFromJson(jsonObj.get(), ""));
    auto jsonRes = GetJsonArrayFromJson(jsonObj.get(), "key");
    EXPECT_TRUE(IsArray(jsonRes));
}

/*
 * @tc.name: PackJsonToMapUint64Int32Test001
 * @tc.desc: PackJsonToMapUint64Int32 with nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, PackJsonToMapUint64Int32Test001, TestSize.Level4)
{
    // Test with nullptr
    std::map<std::uint64_t, std::int32_t> result = PackJsonToMapUint64Int32(nullptr);
    EXPECT_TRUE(result.empty());
}

/*
 * @tc.name: PackJsonToMapUint64Int32Test002
 * @tc.desc: PackJsonToMapUint64Int32 with non-object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, PackJsonToMapUint64Int32Test002, TestSize.Level4)
{
    // Test with array (non-object)
    auto jsonArray = CreateJsonArray();
    std::map<std::uint64_t, std::int32_t> result = PackJsonToMapUint64Int32(jsonArray.get());
    EXPECT_TRUE(result.empty());
}

/*
 * @tc.name: PackJsonToMapUint64Int32Test003
 * @tc.desc: PackJsonToMapUint64Int32 with empty object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, PackJsonToMapUint64Int32Test003, TestSize.Level4)
{
    // Test with empty object
    auto jsonObj = CreateJson();
    std::map<std::uint64_t, std::int32_t> result = PackJsonToMapUint64Int32(jsonObj.get());
    EXPECT_TRUE(result.empty());
}

/*
 * @tc.name: PackJsonToMapUint64Int32Test004
 * @tc.desc: PackJsonToMapUint64Int32 with valid data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, PackJsonToMapUint64Int32Test004, TestSize.Level4)
{
    // Test with valid uint64 key and int32 value
    const std::string jsonStr = "{\"123\":456,\"18446744073709551615\":789}";
    auto jsonObj = CreateJsonFromString(jsonStr);
    std::map<std::uint64_t, std::int32_t> result = PackJsonToMapUint64Int32(jsonObj.get());
    EXPECT_EQ(2, result.size());
    EXPECT_EQ(456, result[123]);
    EXPECT_EQ(789, result[18446744073709551615ULL]);
}

/*
 * @tc.name: PackJsonToMapUint64Int32Test005
 * @tc.desc: PackJsonToMapUint64Int32 with non-number items
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, PackJsonToMapUint64Int32Test005, TestSize.Level4)
{
    // Test with non-number items (should be skipped)
    auto jsonObj = CreateJson();
    EXPECT_TRUE(AddStringToJson(jsonObj, "123", "string_value"));
    EXPECT_TRUE(AddIntToJson(jsonObj, "456", 789));
    std::map<std::uint64_t, std::int32_t> result = PackJsonToMapUint64Int32(jsonObj.get());
    EXPECT_EQ(1, result.size());
    EXPECT_EQ(789, result[456]);
}

/*
 * @tc.name: PackJsonToMapUint64Int32Test006
 * @tc.desc: PackJsonToMapUint64Int32 with invalid key format
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, PackJsonToMapUint64Int32Test006, TestSize.Level4)
{
    // Test with invalid key format (non-numeric string)
    const std::string jsonStr = "{\"abc\":123,\"456\":789}";
    auto jsonObj = CreateJsonFromString(jsonStr);
    std::map<std::uint64_t, std::int32_t> result = PackJsonToMapUint64Int32(jsonObj.get());
    EXPECT_EQ(1, result.size());
    EXPECT_EQ(789, result[456]);
}

/*
 * @tc.name: PackJsonToMapUint64Int32Test007
 * @tc.desc: PackJsonToMapUint64Int32 with CJsonUnique
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonUtilsTest, PackJsonToMapUint64Int32Test007, TestSize.Level4)
{
    // Test CJsonUnique overload
    const std::string jsonStr = "{\"123\":456}";
    auto jsonObj = CreateJsonFromString(jsonStr);
    std::map<std::uint64_t, std::int32_t> result = PackJsonToMapUint64Int32(jsonObj);
    EXPECT_EQ(1, result.size());
    EXPECT_EQ(456, result[123]);
}