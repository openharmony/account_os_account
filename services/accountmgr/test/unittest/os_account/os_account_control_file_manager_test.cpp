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

#include <algorithm>
#include <ctime>
#include <gtest/gtest.h>
#include "os_account_constants.h"
#include "account_error_no.h"
#define private public
#include "os_account_control_file_manager.h"
#undef private
namespace OHOS {
namespace AccountSA {
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS;
using namespace AccountSA;
namespace {
const OsAccountType osAccountType = OsAccountType::ADMIN;
const int INT_TEST_ERR_USER_ID = 1000000;
const std::string STRING_TEST_USER_NAME = "testuser";
const std::string STRING_TEST_USER_NAME_TWO = "testuser2";
const int64_t STRING_TEST_USER_SHELLNUMBER = 1000;
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
const std::string STRING_ERR_PHOTO =
    "FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU/"
    "8AAEQgAEgAOAwEiAAIRAQMRAf/EAB8AAAEFAQEBAQEBAAAAAAAAAAABAgMEBQYHCAkKC//"
    "EALUQAAIBAwMCBAMFBQQEAAABfQECAwAEEQUSITFBBhNRYQcicRQygZGhCCNCscEVUtHwJDNicoIJChYXGBkaJSYnKCkqNDU2Nzg5OkNERUZHS"
    "ElKU"
    "1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6g4SFhoeIiYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV1tfY2drh4uPk5eb"
    "n6On"
    "q8fLz9PX29/j5+v/EAB8BAAMBAQEBAQEBAQEAAAAAAAABAgMEBQYHCAkKC//"
    "EALURAAIBAgQEAwQHBQQEAAECdwABAgMRBAUhMQYSQVEHYXETIjKBCBRCkaGxwQkjM1LwFWJy0QoWJDThJfEXGBkaJicoKSo1Njc4OTpDREVGR"
    "0hJS"
    "lNUVVZXWFlaY2RlZmdoaWpzdHV2d3h5eoKDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uLj5OX"
    "m5+"
    "jp6vLz9PX29/j5+v/aAAwDAQACEQMRAD8A++fid8e7j4ZiYXHgDxBfN5jJayQ3OnBLsKQGdF+1GbYAwJJi4yN2M1seF/"
    "i+fEtnHfv4O8R6dpcoby75ltLxHcNtMeyzuJ5FYEMDuQBSpUkNgH5l+Ndx4XtPix4ik0/"
    "xFpssN5bwwXwPilDIZ0klLxSq2vWLAIWACMjBeilQNo6j9ni50R9U8U6lF400m18Q30sTMLnxC1758CxqrO8EesXXzBgiiV5SQPlCgHnNSfI5f"
    "1+"
    "av33Q5L3rdP68nb7mfWlFFFaCP//Z";
}  // namespace
class OsAccountControlFileManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

public:
    std::shared_ptr<OsAccountControlFileManager> osAccountControlManager_;
};

void OsAccountControlFileManagerTest::SetUpTestCase(void)
{}

void OsAccountControlFileManagerTest::TearDownTestCase(void)
{}

void OsAccountControlFileManagerTest::SetUp(void)
{
    osAccountControlManager_ = std::make_shared<OsAccountControlFileManager>();
    osAccountControlManager_->Init();
}

void OsAccountControlFileManagerTest::TearDown(void)
{}

/**
 * @tc.name: OsAccountControlFileManagerTest001
 * @tc.desc: Test GetOsAccountList
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerTest001, TestSize.Level1)
{
    std::vector<OsAccountInfo> osAccountInfos;
    EXPECT_EQ(osAccountControlManager_->GetOsAccountList(osAccountInfos), ERR_OK);
    const unsigned int size = 0;
    EXPECT_NE(osAccountInfos.size(), size);
}

/**
 * @tc.name: OsAccountControlFileManagerTest002
 * @tc.desc: Test GetOsAccountInfoById by valid data
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerTest002, TestSize.Level0)
{
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(osAccountControlManager_->GetOsAccountInfoById(Constants::START_USER_ID, osAccountInfo), ERR_OK);
    EXPECT_EQ(osAccountInfo.GetLocalName(), Constants::STANDARD_LOCAL_NAME);
}

/**
 * @tc.name: OsAccountControlFileManagerTest003
 * @tc.desc: Test GetOsAccountInfoById by unvalid data
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerTest003, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    int id = Constants::MAX_USER_ID + 1;
    EXPECT_NE(osAccountControlManager_->GetOsAccountInfoById(id, osAccountInfo), ERR_OK);
}

/**
 * @tc.name: OsAccountControlFileManagerTest004
 * @tc.desc: Test GetConstraintsByType
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerTest004, TestSize.Level1)
{
    std::vector<std::string> constratins;
    EXPECT_EQ(osAccountControlManager_->GetConstraintsByType(OsAccountType::ADMIN, constratins), ERR_OK);
    const unsigned int size = 0;
    EXPECT_NE(size, constratins.size());
}

/**
 * @tc.name: OsAccountControlFileManagerTest005
 * @tc.desc: Test GetConstraintsByType by other type
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerTest005, TestSize.Level1)
{
    std::vector<std::string> constratins;
    EXPECT_EQ(osAccountControlManager_->GetConstraintsByType(OsAccountType::GUEST, constratins), ERR_OK);
}

/**
 * @tc.name: OsAccountControlFileManagerTest006
 * @tc.desc: Test GetSerialNumber
 * @tc.type: FUNC
 * @tc.require: SR000GGV0U
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerTest006, TestSize.Level1)
{
    int64_t serialNumber_1;
    int64_t serialNumber_2;
    EXPECT_EQ(osAccountControlManager_->GetSerialNumber(serialNumber_1), ERR_OK);
    EXPECT_EQ(osAccountControlManager_->GetSerialNumber(serialNumber_2), ERR_OK);
    EXPECT_EQ(serialNumber_1 + 1, serialNumber_2);
}

/**
 * @tc.name: OsAccountControlFileManagerTest007
 * @tc.desc: Test IsOsAccountExists
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerTest007, TestSize.Level1)
{
    bool isOsAccountExists = false;
    EXPECT_EQ(osAccountControlManager_->IsOsAccountExists(Constants::START_USER_ID, isOsAccountExists), ERR_OK);
    EXPECT_EQ(isOsAccountExists, true);
}

/**
 * @tc.name: OsAccountControlFileManagerTest008
 * @tc.desc: Test IsOsAccountExists
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerTest008, TestSize.Level1)
{
    bool isOsAccountExists = true;
    int id = Constants::MAX_USER_ID + 1;
    EXPECT_EQ(osAccountControlManager_->IsOsAccountExists(id, isOsAccountExists), ERR_OK);
    EXPECT_EQ(isOsAccountExists, false);
}

/**
 * @tc.name: OsAccountControlFileManagerTest009
 * @tc.desc: Test GetMaxCreatedOsAccountNum
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerTest009, TestSize.Level1)
{
    int maxCreatedOsAccountNum = 0;
    EXPECT_EQ(osAccountControlManager_->GetMaxCreatedOsAccountNum(maxCreatedOsAccountNum), ERR_OK);
    EXPECT_NE(maxCreatedOsAccountNum, 0);
}

/**
 * @tc.name: OsAccountControlFileManagerTest010
 * @tc.desc: Test GetAllowCreateId
 * @tc.type: FUNC
 * @tc.require: SR000GGV0U
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerTest010, TestSize.Level1)
{
    int id = 0;
    EXPECT_EQ(osAccountControlManager_->GetAllowCreateId(id), ERR_OK);
    EXPECT_NE(id, 0);
    bool isOsAccountExists = true;
    EXPECT_EQ(osAccountControlManager_->IsOsAccountExists(id, isOsAccountExists), ERR_OK);
    EXPECT_EQ(isOsAccountExists, false);
}

/**
 * @tc.name: OsAccountControlFileManagerTest011
 * @tc.desc: Test InsertOsAccount
 * @tc.type: FUNC
 * @tc.require: SR000GGV0U
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerTest011, TestSize.Level1)
{
    int id = 0;
    osAccountControlManager_->GetAllowCreateId(id);
    OsAccountInfo osAccountInfo(id, STRING_TEST_USER_NAME, osAccountType, STRING_TEST_USER_SHELLNUMBER);
    EXPECT_EQ(osAccountControlManager_->InsertOsAccount(osAccountInfo), ERR_OK);
    bool isOsAccountExists = false;
    EXPECT_EQ(osAccountControlManager_->IsOsAccountExists(id, isOsAccountExists), ERR_OK);
    EXPECT_NE(isOsAccountExists, false);
    osAccountControlManager_->DelOsAccount(id);
}

/**
 * @tc.name: OsAccountControlFileManagerTest012
 * @tc.desc: Test InsertOsAccount with unvalid data
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerTest012, TestSize.Level1)
{
    OsAccountInfo osAccountInfo(
        INT_TEST_ERR_USER_ID, STRING_TEST_USER_NAME, osAccountType, STRING_TEST_USER_SHELLNUMBER);
    EXPECT_EQ(osAccountControlManager_->InsertOsAccount(osAccountInfo),
        ERR_OS_ACCOUNT_SERVICE_CONTROL_ID_CANNOT_CREATE_ERROR);
}

/**
 * @tc.name: OsAccountControlFileManagerTest013
 * @tc.desc: Test InsertOsAccount with unvalid data
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerTest013, TestSize.Level1)
{
    OsAccountInfo osAccountInfo(
        Constants::START_USER_ID, STRING_TEST_USER_NAME, osAccountType, STRING_TEST_USER_SHELLNUMBER);
    EXPECT_EQ(osAccountControlManager_->InsertOsAccount(osAccountInfo),
        ERR_OS_ACCOUNT_SERVICE_CONTROL_INSERT_FILE_EXISTS_ERROR);
}

/**
 * @tc.name: OsAccountControlFileManagerTest014
 * @tc.desc: Test DelOsAccount
 * @tc.type: FUNC
 * @tc.require: SR000GGV0U
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerTest014, TestSize.Level0)
{
    int id = 0;
    osAccountControlManager_->GetAllowCreateId(id);
    OsAccountInfo osAccountInfo(id, STRING_TEST_USER_NAME, osAccountType, STRING_TEST_USER_SHELLNUMBER);
    EXPECT_EQ(osAccountControlManager_->InsertOsAccount(osAccountInfo), ERR_OK);
    OsAccountInfo osAccountInfoTwo;
    osAccountControlManager_->GetOsAccountInfoById(id, osAccountInfoTwo);
    EXPECT_EQ(osAccountInfoTwo.GetLocalName(), STRING_TEST_USER_NAME);
    EXPECT_EQ(osAccountControlManager_->DelOsAccount(id), ERR_OK);
}

/**
 * @tc.name: OsAccountControlFileManagerTest015
 * @tc.desc: Test DelOsAccount with unvalid data
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerTest015, TestSize.Level1)
{
    int id = Constants::ADMIN_LOCAL_ID;
    EXPECT_NE(osAccountControlManager_->DelOsAccount(id), ERR_OK);
}

/**
 * @tc.name: OsAccountControlFileManagerTest016
 * @tc.desc: Test DelOsAccount
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerTest016, TestSize.Level1)
{
    int id = Constants::START_USER_ID;
    EXPECT_NE(osAccountControlManager_->DelOsAccount(id), ERR_OK);
}

/**
 * @tc.name: OsAccountControlFileManagerTest017
 * @tc.desc: Test UpdateOsAccount
 * @tc.type: FUNC
 * @tc.require: SR000GGVFI
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerTest017, TestSize.Level0)
{
    int id = 0;
    osAccountControlManager_->GetAllowCreateId(id);
    OsAccountInfo osAccountInfo(id, STRING_TEST_USER_NAME, osAccountType, STRING_TEST_USER_SHELLNUMBER);
    osAccountControlManager_->InsertOsAccount(osAccountInfo);
    osAccountInfo.SetLocalName(STRING_TEST_USER_NAME_TWO);
    EXPECT_EQ(osAccountControlManager_->UpdateOsAccount(osAccountInfo), ERR_OK);
    OsAccountInfo osAccountInfoTwo;
    osAccountControlManager_->GetOsAccountInfoById(id, osAccountInfoTwo);
    EXPECT_EQ(osAccountInfoTwo.GetLocalName(), STRING_TEST_USER_NAME_TWO);
    osAccountControlManager_->DelOsAccount(id);
}

/**
 * @tc.name: OsAccountControlFileManagerTest018
 * @tc.desc: Test SetPhotoById and GetPhotoById
 * @tc.type: FUNC
 * @tc.require: SR000GGVFI
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerTest018, TestSize.Level1)
{
    int id = 0;
    osAccountControlManager_->GetAllowCreateId(id);
    OsAccountInfo osAccountInfo(id, STRING_TEST_USER_NAME, osAccountType, STRING_TEST_USER_SHELLNUMBER);
    osAccountControlManager_->InsertOsAccount(osAccountInfo);
    EXPECT_EQ(osAccountControlManager_->SetPhotoById(id, STRING_PHOTO), ERR_OK);
    std::string photo = Constants::USER_PHOTO_FILE_JPG_NAME;
    EXPECT_EQ(osAccountControlManager_->GetPhotoById(id, photo), ERR_OK);
    EXPECT_EQ(photo, STRING_PHOTO);
    osAccountControlManager_->DelOsAccount(id);
}

/**
 * @tc.name: OsAccountControlFileManagerTest019
 * @tc.desc: Test SetPhotoById
 * @tc.type: FUNC
 * @tc.require: SR000GGVFI
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerTest019, TestSize.Level1)
{
    int id = 0;
    osAccountControlManager_->GetAllowCreateId(id);
    OsAccountInfo osAccountInfo(id, STRING_TEST_USER_NAME, osAccountType, STRING_TEST_USER_SHELLNUMBER);
    osAccountControlManager_->InsertOsAccount(osAccountInfo);
    EXPECT_NE(osAccountControlManager_->SetPhotoById(id, STRING_ERR_PHOTO), ERR_OK);
    osAccountControlManager_->DelOsAccount(id);
}
}  // namespace AccountSA
}  // namespace OHOS