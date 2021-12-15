/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#define private public
#include "os_account_info.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const int INT_ID = 12;
const std::string STRING_NAME = "account";
const int INT_TYPE = 123;
const int64_t STRING_SERIAL_NUMBER = 121012012;
const std::vector<std::string> VECTOR_CONSTRAINTS {"one", "two", "three", "four", "five"};
const bool BOOL_IS_OS_ACCOUNT_VERIFIED = true;
const bool BOOL_IS_OS_ACCOUNT_COMPLETED = true;
const bool BOOL_IS_ACTIVED = true;
const std::string STRING_PHOTO =
    "data:image/jpeg;base64,/9j/4AAQSkZJRgABAQEAYABgAAD//gAUU29mdHdhcmU6IFNuaXBhc3Rl/"
    "9sAQwADAgIDAgIDAwMDBAMDBAUIBQUEBAUKBwcGCAwKDAwLCgsLDQ4SEA0OEQ4LCxAWEBETFBUVFQwPFxgWFBgSFBUU/"
    "9sAQwEDBAQFBAUJBQUJFA0LDRQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU/"
    "8AAEQgAEgAOAwEiAAIRAQMRAf/EAB8AAAEFAQEBAQEBAAAAAAAAAAABAgMEBQYHCAkKC//"
    "EALUQAAIBAwMCBAMFBQQEAAABfQECAwAEEQUSITFBBhNRYQcicRQygZGhCCNCscEVUtHwJDNicoIJChYXGBkaJSYnKCkqNDU2Nzg5OkNERUZHSElKU"
    "1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6g4SFhoeIiYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV1tfY2drh4uPk5ebn6On"
    "q8fLz9PX29/j5+v/EAB8BAAMBAQEBAQEBAQEAAAAAAAABAgMEBQYHCAkKC//"
    "EALURAAIBAgQEAwQHBQQEAAECdwABAgMRBAUhMQYSQVEHYXETIjKBCBRCkaGxwQkjM1LwFWJy0QoWJDThJfEXGBkaJicoKSo1Njc4OTpDREVGR0hJS"
    "lNUVVZXWFlaY2RlZmdoaWpzdHV2d3h5eoKDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uLj5OXm5+"
    "jp6vLz9PX29/j5+v/aAAwDAQACEQMRAD8A++fid8e7j4ZiYXHgDxBfN5jJayQ3OnBLsKQGdF+1GbYAwJJi4yN2M1seF/"
    "i+fEtnHfv4O8R6dpcoby75ltLxHcNtMeyzuJ5FYEMDuQBSpUkNgH5l+Ndx4XtPix4ik0/"
    "xFpssN5bwwXwPilDIZ0klLxSq2vWLAIWACMjBeilQNo6j9ni50R9U8U6lF400m18Q30sTMLnxC1758CxqrO8EesXXzBgiiV5SQPlCgHnNSfI5f1+"
    "av33Q5L3rdP68nb7mfWlFFFaCP//Z";
const int64_t INT_CREATE_TIME = 1551925510;
const int64_t INT_LAST_LOGINGGED_IN_TIME = 1551925510;
const std::string STRING_JSON =
    "{\"constraints\":[\"one\",\"two\",\"three\",\"four\",\"five\"],\"createTime\":1551925510,"
    "\"id\":12,\"isAccountCompleted\":true,\"isActived\":false,\"isOsAccountVerified\":true,\"lastLoggedInTime\":"
    "1551925510,\"name\":\"account\",\"photo\":\"data:image/jpeg;base64,/9j/4AAQSkZJRgABAQEAYABgAAD//"
    "gAUU29mdHdhcmU6IFNuaXBhc3Rl/"
    "9sAQwADAgIDAgIDAwMDBAMDBAUIBQUEBAUKBwcGCAwKDAwLCgsLDQ4SEA0OEQ4LCxAWEBETFBUVFQwPFxgWFBgSFBUU/"
    "9sAQwEDBAQFBAUJBQUJFA0LDRQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU/"
    "8AAEQgAEgAOAwEiAAIRAQMRAf/EAB8AAAEFAQEBAQEBAAAAAAAAAAABAgMEBQYHCAkKC//"
    "EALUQAAIBAwMCBAMFBQQEAAABfQECAwAEEQUSITFBBhNRYQcicRQygZGhCCNCscEVUtHwJDNicoIJChYXGBkaJSYnKCkqNDU2Nzg5OkNERUZHSElKU"
    "1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6g4SFhoeIiYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV1tfY2drh4uPk5ebn6On"
    "q8fLz9PX29/j5+v/EAB8BAAMBAQEBAQEBAQEAAAAAAAABAgMEBQYHCAkKC//"
    "EALURAAIBAgQEAwQHBQQEAAECdwABAgMRBAUhMQYSQVEHYXETIjKBCBRCkaGxwQkjM1LwFWJy0QoWJDThJfEXGBkaJicoKSo1Njc4OTpDREVGR0hJS"
    "lNUVVZXWFlaY2RlZmdoaWpzdHV2d3h5eoKDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uLj5OXm5+"
    "jp6vLz9PX29/j5+v/aAAwDAQACEQMRAD8A++fid8e7j4ZiYXHgDxBfN5jJayQ3OnBLsKQGdF+1GbYAwJJi4yN2M1seF/"
    "i+fEtnHfv4O8R6dpcoby75ltLxHcNtMeyzuJ5FYEMDuQBSpUkNgH5l+Ndx4XtPix4ik0/"
    "xFpssN5bwwXwPilDIZ0klLxSq2vWLAIWACMjBeilQNo6j9ni50R9U8U6lF400m18Q30sTMLnxC1758CxqrO8EesXXzBgiiV5SQPlCgHnNSfI5f1+"
    "av33Q5L3rdP68nb7mfWlFFFaCP//Z\",\"serialNumber\":121012012,\"type\":123}";
}  // namespace
class OsAccountInfoTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

void OsAccountInfoTest::SetUpTestCase(void)
{}

void OsAccountInfoTest::TearDownTestCase(void)
{}

void OsAccountInfoTest::SetUp(void)
{}

void OsAccountInfoTest::TearDown(void)
{}

/**
 * @tc.name: OsAccountInfo_OsAccountInfo_0100
 * @tc.desc: Create a OsAccountInfo object with no parameter.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountInfoTest, OsAccountInfo_OsAccountInfo_0100, Function | MediumTest | Level1)
{
    OsAccountInfo *osAccountInfo = new (std::nothrow) OsAccountInfo();
    EXPECT_NE(osAccountInfo, nullptr);
    delete (osAccountInfo);
}

/**
 * @tc.name: OsAccountInfo_OsAccountInfo_0200
 * @tc.desc: Create a OsAccountInfo object with four parameters.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountInfoTest, OsAccountInfo_OsAccountInfo_0200, Function | MediumTest | Level1)
{
    OsAccountInfo *osAccountInfo =
        new (std::nothrow) OsAccountInfo(INT_ID, STRING_NAME, INT_TYPE, STRING_SERIAL_NUMBER);
    EXPECT_NE(osAccountInfo, nullptr);
    delete (osAccountInfo);
}

/**
 * @tc.name: OsAccountInfo_OsAccountInfo_0300
 * @tc.desc: Create a OsAccountInfo object with eleven parameters.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountInfoTest, OsAccountInfo_OsAccountInfo_0300, Function | MediumTest | Level1)
{
    OsAccountInfo *osAccountInfo = new (std::nothrow) OsAccountInfo(INT_ID,
        STRING_NAME,
        INT_TYPE,
        VECTOR_CONSTRAINTS,
        BOOL_IS_OS_ACCOUNT_VERIFIED,
        STRING_PHOTO,
        INT_CREATE_TIME,
        INT_LAST_LOGINGGED_IN_TIME,
        STRING_SERIAL_NUMBER,
        BOOL_IS_OS_ACCOUNT_COMPLETED);
    EXPECT_NE(osAccountInfo, nullptr);
    delete (osAccountInfo);
}

/**
 * @tc.name: OsAccountInfo_GetId_0100
 * @tc.desc: Get the id with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountInfoTest, OsAccountInfo_GetId_0100, Function | MediumTest | Level1)
{
    int id = INT_ID;
    OsAccountInfo osAccountInfo;
    osAccountInfo.id_ = id;
    EXPECT_EQ(id, osAccountInfo.GetId());
}

/**
 * @tc.name: OsAccountInfo_SetId_0100
 * @tc.desc: Set the id with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountInfoTest, OsAccountInfo_SetId_0100, Function | MediumTest | Level1)
{
    OsAccountInfo osAccountInfo;
    osAccountInfo.SetId(INT_ID);
    EXPECT_EQ(INT_ID, osAccountInfo.id_);
}

/**
 * @tc.name: OsAccountInfo_GetName_0100
 * @tc.desc: Get the name with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountInfoTest, OsAccountInfo_GetName_0100, Function | MediumTest | Level1)
{
    std::string name = STRING_NAME;
    OsAccountInfo osAccountInfo;
    osAccountInfo.name_ = name;
    EXPECT_EQ(name, osAccountInfo.GetName());
}

/**
 * @tc.name: OsAccountInfo_SetName_0100
 * @tc.desc: Set the name with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountInfoTest, OsAccountInfo_SetName_0100, Function | MediumTest | Level1)
{
    OsAccountInfo osAccountInfo;
    osAccountInfo.SetName(STRING_NAME);
    EXPECT_EQ(STRING_NAME, osAccountInfo.name_);
}

/**
 * @tc.name: OsAccountInfo_GetType_0100
 * @tc.desc: Get the type with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountInfoTest, OsAccountInfo_GetType_0100, Function | MediumTest | Level1)
{
    int type = INT_TYPE;
    OsAccountInfo osAccountInfo;
    osAccountInfo.type_ = type;
    EXPECT_EQ(type, osAccountInfo.GetType());
}

/**
 * @tc.name: OsAccountInfo_SetType_0100
 * @tc.desc: Set the type with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountInfoTest, OsAccountInfo_SetType_0100, Function | MediumTest | Level1)
{
    OsAccountInfo osAccountInfo;
    osAccountInfo.SetType(INT_TYPE);
    EXPECT_EQ(INT_TYPE, osAccountInfo.type_);
}

/**
 * @tc.name: OsAccountInfo_GetConstraints_0100
 * @tc.desc: Get the Constraints with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountInfoTest, OsAccountInfo_GetConstraints_0100, Function | MediumTest | Level1)
{
    std::vector<std::string> constraints = VECTOR_CONSTRAINTS;
    OsAccountInfo osAccountInfo;
    osAccountInfo.constraints_ = constraints;
    EXPECT_EQ(constraints.size(), osAccountInfo.GetConstraints().size());
}

/**
 * @tc.name: OsAccountInfo_SetConstraints_0100
 * @tc.desc: Set the Constraints with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountInfoTest, OsAccountInfo_SetConstraints_0100, Function | MediumTest | Level1)
{
    OsAccountInfo osAccountInfo;
    osAccountInfo.SetConstraints(VECTOR_CONSTRAINTS);
    EXPECT_EQ(VECTOR_CONSTRAINTS.size(), osAccountInfo.constraints_.size());
}

/**
 * @tc.name: OsAccountInfo_GetIsAccountVerified_0100
 * @tc.desc: Get the isAccountVerified with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountInfoTest, OsAccountInfo_GetIsAccountVerified_0100, Function | MediumTest | Level1)
{
    bool isAccountVerified = BOOL_IS_OS_ACCOUNT_VERIFIED;
    OsAccountInfo osAccountInfo;
    osAccountInfo.isAccountVerified_ = isAccountVerified;
    EXPECT_EQ(isAccountVerified, osAccountInfo.GetIsAccountVerified());
}

/**
 * @tc.name: OsAccountInfo_SetIsAccountVerified_0100
 * @tc.desc: Set the isAccountVerified with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountInfoTest, OsAccountInfo_SetIsAccountVerified_0100, Function | MediumTest | Level1)
{
    OsAccountInfo osAccountInfo;
    osAccountInfo.SetIsAccountVerified(BOOL_IS_OS_ACCOUNT_VERIFIED);
    EXPECT_EQ(BOOL_IS_OS_ACCOUNT_VERIFIED, osAccountInfo.isAccountVerified_);
}

/**
 * @tc.name: OsAccountInfo_GetIsAccountCompleted_0100
 * @tc.desc: Get the isAccountCompleted with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountInfoTest, OsAccountInfo_GetIsAccountCompleted_0100, Function | MediumTest | Level1)
{
    bool isAccountCompleted = BOOL_IS_OS_ACCOUNT_COMPLETED;
    OsAccountInfo osAccountInfo;
    osAccountInfo.isAccountCompleted_ = isAccountCompleted;
    EXPECT_EQ(isAccountCompleted, osAccountInfo.GetIsAccountCompleted());
}

/**
 * @tc.name: OsAccountInfo_SetIsAccountCompleted_0100
 * @tc.desc: Set the isAccountCompleted with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountInfoTest, OsAccountInfo_SetIsAccountCompleted_0100, Function | MediumTest | Level1)
{
    OsAccountInfo osAccountInfo;
    osAccountInfo.SetIsAccountCompleted(BOOL_IS_OS_ACCOUNT_COMPLETED);
    EXPECT_EQ(BOOL_IS_OS_ACCOUNT_COMPLETED, osAccountInfo.isAccountCompleted_);
}

/**
 * @tc.name: OsAccountInfo_GetIsActived_0100
 * @tc.desc: Get the isActived with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountInfoTest, OsAccountInfo_GetIsActived_0100, Function | MediumTest | Level1)
{
    bool isActived = BOOL_IS_ACTIVED;
    OsAccountInfo osAccountInfo;
    osAccountInfo.isActived_ = isActived;
    EXPECT_EQ(isActived, osAccountInfo.GetIsActived());
}

/**
 * @tc.name: OsAccountInfo_SetIsActived_0100
 * @tc.desc: Set the isActived with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountInfoTest, OsAccountInfo_SetIsActived_0100, Function | MediumTest | Level1)
{
    OsAccountInfo osAccountInfo;
    osAccountInfo.SetIsActived(BOOL_IS_ACTIVED);
    EXPECT_EQ(BOOL_IS_ACTIVED, osAccountInfo.isActived_);
}

/**
 * @tc.name: OsAccountInfo_GetPhoto_0100
 * @tc.desc: Get the photo with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountInfoTest, OsAccountInfo_GetPhoto_0100, Function | MediumTest | Level1)
{
    std::string photo = STRING_PHOTO;
    OsAccountInfo osAccountInfo;
    osAccountInfo.photo_ = photo;
    EXPECT_EQ(photo, osAccountInfo.GetPhoto());
}

/**
 * @tc.name: OsAccountInfo_SetPhoto_0100
 * @tc.desc: Set the photo with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountInfoTest, OsAccountInfo_SetPhoto_0100, Function | MediumTest | Level1)
{
    OsAccountInfo osAccountInfo;
    osAccountInfo.SetPhoto(STRING_PHOTO);
    EXPECT_EQ(STRING_PHOTO, osAccountInfo.photo_);
}

/**
 * @tc.name: OsAccountInfo_GetCreateTime_0100
 * @tc.desc: Get the createTime with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountInfoTest, OsAccountInfo_GetCreateTime_0100, Function | MediumTest | Level1)
{
    int64_t createTime = INT_CREATE_TIME;
    OsAccountInfo osAccountInfo;
    osAccountInfo.createTime_ = createTime;
    EXPECT_EQ(createTime, osAccountInfo.GetCreateTime());
}

/**
 * @tc.name: OsAccountInfo_SetCreateTime_0100
 * @tc.desc: Set the createTime with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountInfoTest, OsAccountInfo_SetCreateTime_0100, Function | MediumTest | Level1)
{
    OsAccountInfo osAccountInfo;
    osAccountInfo.SetCreateTime(INT_CREATE_TIME);
    EXPECT_EQ(INT_CREATE_TIME, osAccountInfo.createTime_);
}

/**
 * @tc.name: OsAccountInfo_GetLastLoggedInTime_0100
 * @tc.desc: Get the lastLoggedInTime with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountInfoTest, OsAccountInfo_GetLastLoggedInTime_0100, Function | MediumTest | Level1)
{
    int64_t lastLoggedInTime = INT_LAST_LOGINGGED_IN_TIME;
    OsAccountInfo osAccountInfo;
    osAccountInfo.lastLoggedInTime_ = lastLoggedInTime;
    EXPECT_EQ(lastLoggedInTime, osAccountInfo.GetLastLoggedInTime());
}

/**
 * @tc.name: OsAccountInfo_GetSerialNumber_0100
 * @tc.desc: Get the serialNumber with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountInfoTest, OsAccountInfo_GetSerialNumber_0100, Function | MediumTest | Level1)
{
    int64_t serialNumber = STRING_SERIAL_NUMBER;
    OsAccountInfo osAccountInfo;
    osAccountInfo.serialNumber_ = serialNumber;
    EXPECT_EQ(serialNumber, osAccountInfo.GetSerialNumber());
}

/**
 * @tc.name: OsAccountInfo_SetSerialNumber_0100
 * @tc.desc: Set the serialNumber with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountInfoTest, OsAccountInfo_SetSerialNumber_0100, Function | MediumTest | Level1)
{
    OsAccountInfo osAccountInfo;
    osAccountInfo.SetSerialNumber(STRING_SERIAL_NUMBER);
    EXPECT_EQ(STRING_SERIAL_NUMBER, osAccountInfo.serialNumber_);
}

/**
 * @tc.name: OsAccountInfo_ToJson_0100
 * @tc.desc: Get the Json with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountInfoTest, OsAccountInfo_ToJson_0100, Function | MediumTest | Level1)
{
    OsAccountInfo osAccountInfo(INT_ID,
        STRING_NAME,
        INT_TYPE,
        VECTOR_CONSTRAINTS,
        BOOL_IS_OS_ACCOUNT_VERIFIED,
        STRING_PHOTO,
        INT_CREATE_TIME,
        INT_LAST_LOGINGGED_IN_TIME,
        STRING_SERIAL_NUMBER,
        BOOL_IS_OS_ACCOUNT_COMPLETED);
    std::string jsonStr = osAccountInfo.ToJson().dump();
    EXPECT_EQ(jsonStr, STRING_JSON);
    GTEST_LOG_(INFO) << jsonStr;
}

/**
 * @tc.name: OsAccountInfo_FromJson_0100
 * @tc.desc: Set a object by Json.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountInfoTest, OsAccountInfo_FromJson_0100, Function | MediumTest | Level1)
{
    OsAccountInfo osAccountInfo;

    osAccountInfo.FromJson(Json::parse(STRING_JSON, nullptr, false));
    EXPECT_EQ(osAccountInfo.GetId(), INT_ID);
}

/**
 * @tc.name: OsAccountInfo_ToString_0100
 * @tc.desc: ToString
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountInfoTest, OsAccountInfo_ToString_0100, Function | MediumTest | Level1)
{
    OsAccountInfo osAccountInfo(INT_ID,
        STRING_NAME,
        INT_TYPE,
        VECTOR_CONSTRAINTS,
        BOOL_IS_OS_ACCOUNT_VERIFIED,
        STRING_PHOTO,
        INT_CREATE_TIME,
        INT_LAST_LOGINGGED_IN_TIME,
        STRING_SERIAL_NUMBER,
        BOOL_IS_OS_ACCOUNT_COMPLETED);
    std::string stringStr = osAccountInfo.ToString();
    EXPECT_EQ(stringStr, STRING_JSON);
}
