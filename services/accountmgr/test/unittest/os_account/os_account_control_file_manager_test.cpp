/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include <iostream>
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "os_account_constants.h"
#define private public
#include "os_account_control_file_manager.h"
#undef private
#include "parameter.h"

namespace OHOS {
namespace AccountSA {
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS;
using namespace AccountSA;
namespace {
const OsAccountType OS_ACCOUNT_TYPE = OsAccountType::ADMIN;
const int INT_TEST_ERR_USER_ID = 1000000;
const std::string STRING_TEST_USER_NAME = "testuser";
const std::string STRING_TEST_USER_NAME_TWO = "testuser2";
const int64_t STRING_TEST_USER_SHELLNUMBER = 1000;
const int32_t INVALID_TYPE = 100000;
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
    std::string storeID_;
};

void OsAccountControlFileManagerTest::SetUpTestCase(void)
{}

void OsAccountControlFileManagerTest::TearDownTestCase(void)
{}

void OsAccountControlFileManagerTest::SetUp(void)
{
    osAccountControlManager_ = std::make_shared<OsAccountControlFileManager>();
    osAccountControlManager_->Init();

    char udid[Constants::DEVICE_UUID_LENGTH] = {0};
    int ret = GetDevUdid(udid, Constants::DEVICE_UUID_LENGTH);
    if (ret != 0) {
        std::cout << "Error: GetDevUdid failed! errcode " << ret << std::endl;
    } else {
        storeID_ = std::string(udid);
        std::cout << "Info : GetDevUdid succeed! storeID_ " << storeID_ << std::endl;
    }
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
 * @tc.desc: Test GetOsAccountInfoById by invalid data
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
    std::vector<std::string> constraints;
    EXPECT_EQ(osAccountControlManager_->GetConstraintsByType(OsAccountType::ADMIN, constraints), ERR_OK);
    const unsigned int size = 0;
    EXPECT_NE(size, constraints.size());
}

/**
 * @tc.name: OsAccountControlFileManagerTest005
 * @tc.desc: Test GetConstraintsByType by other type
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerTest005, TestSize.Level1)
{
    std::vector<std::string> constraints;
    EXPECT_EQ(osAccountControlManager_->GetConstraintsByType(OsAccountType::GUEST, constraints), ERR_OK);
}

/**
 * @tc.name: OsAccountControlFileManagerTest006
 * @tc.desc: Test GetSerialNumber
 * @tc.type: FUNC
 * @tc.require: SR000GGV0U
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerTest006, TestSize.Level1)
{
    int64_t serialNumber1;
    int64_t serialNumber2;
    EXPECT_EQ(osAccountControlManager_->GetSerialNumber(serialNumber1), ERR_OK);
    EXPECT_EQ(osAccountControlManager_->GetSerialNumber(serialNumber2), ERR_OK);
    EXPECT_EQ(serialNumber1 + 1, serialNumber2);
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
    OsAccountInfo osAccountInfo(id, STRING_TEST_USER_NAME, OS_ACCOUNT_TYPE, STRING_TEST_USER_SHELLNUMBER);
    EXPECT_EQ(osAccountControlManager_->InsertOsAccount(osAccountInfo), ERR_OK);
    bool isOsAccountExists = false;
    EXPECT_EQ(osAccountControlManager_->IsOsAccountExists(id, isOsAccountExists), ERR_OK);
    EXPECT_NE(isOsAccountExists, false);
    osAccountControlManager_->DelOsAccount(id);
}

/**
 * @tc.name: OsAccountControlFileManagerTest012
 * @tc.desc: Test InsertOsAccount with invalid data
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerTest012, TestSize.Level1)
{
    OsAccountInfo osAccountInfo(
        INT_TEST_ERR_USER_ID, STRING_TEST_USER_NAME, OS_ACCOUNT_TYPE, STRING_TEST_USER_SHELLNUMBER);
    EXPECT_EQ(osAccountControlManager_->InsertOsAccount(osAccountInfo),
        ERR_OSACCOUNT_SERVICE_CONTROL_ID_CANNOT_CREATE_ERROR);
}

/**
 * @tc.name: OsAccountControlFileManagerTest013
 * @tc.desc: Test InsertOsAccount with invalid data
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerTest013, TestSize.Level1)
{
    OsAccountInfo osAccountInfo(
        Constants::START_USER_ID, STRING_TEST_USER_NAME, OS_ACCOUNT_TYPE, STRING_TEST_USER_SHELLNUMBER);
    EXPECT_EQ(osAccountControlManager_->InsertOsAccount(osAccountInfo),
        ERR_OSACCOUNT_SERVICE_CONTROL_INSERT_FILE_EXISTS_ERROR);
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
    OsAccountInfo osAccountInfo(id, STRING_TEST_USER_NAME, OS_ACCOUNT_TYPE, STRING_TEST_USER_SHELLNUMBER);
    EXPECT_EQ(osAccountControlManager_->InsertOsAccount(osAccountInfo), ERR_OK);
    OsAccountInfo osAccountInfoTwo;
    osAccountControlManager_->GetOsAccountInfoById(id, osAccountInfoTwo);
    EXPECT_EQ(osAccountInfoTwo.GetLocalName(), STRING_TEST_USER_NAME);
    EXPECT_EQ(osAccountControlManager_->DelOsAccount(id), ERR_OK);
}

/**
 * @tc.name: OsAccountControlFileManagerTest015
 * @tc.desc: Test DelOsAccount with invalid data
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
    OsAccountInfo osAccountInfo(id, STRING_TEST_USER_NAME, OS_ACCOUNT_TYPE, STRING_TEST_USER_SHELLNUMBER);
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
    OsAccountInfo osAccountInfo(id, STRING_TEST_USER_NAME, OS_ACCOUNT_TYPE, STRING_TEST_USER_SHELLNUMBER);
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
    OsAccountInfo osAccountInfo(id, STRING_TEST_USER_NAME, OS_ACCOUNT_TYPE, STRING_TEST_USER_SHELLNUMBER);
    osAccountControlManager_->InsertOsAccount(osAccountInfo);
    EXPECT_NE(osAccountControlManager_->SetPhotoById(id, STRING_ERR_PHOTO), ERR_OK);
    osAccountControlManager_->DelOsAccount(id);
}

/**
 * @tc.name: OsAccountControlFileManagerTest020
 * @tc.desc: GetCreatedOsAccountNumFromDatabase
 * @tc.type: FUNC
 * @tc.require: SR000GGVFK
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerTest020, TestSize.Level1)
{
    int createdOsAccountNum = -1;
    ErrCode ret = osAccountControlManager_->GetCreatedOsAccountNumFromDatabase(storeID_, createdOsAccountNum);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(createdOsAccountNum, 0);
    EXPECT_NE(createdOsAccountNum, -1);

    int64_t serialNumber = -1;
    ret = osAccountControlManager_->GetSerialNumberFromDatabase(storeID_, serialNumber);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(serialNumber, -1);

    int id = -1;
    ret = osAccountControlManager_->GetMaxAllowCreateIdFromDatabase(storeID_, id);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(id, Constants::MAX_USER_ID);

    std::vector<OsAccountInfo> osAccountList;
    ret = osAccountControlManager_->GetOsAccountListFromDatabase(storeID_, osAccountList);
    EXPECT_EQ(ret, ERR_OK);

    for (uint32_t i = 0; i < osAccountList.size(); ++i) {
        int curID = osAccountList[i].GetLocalId();
        bool checkIdValid = (curID >= Constants::START_USER_ID);
        EXPECT_EQ(checkIdValid, true);

        OsAccountInfo curOsAccountInfo;
        ret = osAccountControlManager_->GetOsAccountFromDatabase(storeID_, curID, curOsAccountInfo);
        EXPECT_EQ(ret, ERR_OK);
        EXPECT_EQ(curID, curOsAccountInfo.GetLocalId());
    }
}

/**
 * @tc.name: OsAccountControlFileManagerTest021
 * @tc.desc: GetCreatedOsAccountNumFromDatabase use default parameter
 * @tc.type: FUNC
 * @tc.require: SR000GGVFK
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerTest021, TestSize.Level1)
{
    int createdOsAccountNum = -1;
    ErrCode ret = osAccountControlManager_->GetCreatedOsAccountNumFromDatabase(storeID_, createdOsAccountNum);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(createdOsAccountNum, -1);

    int createdOsAccountNumByDefault = -1;
    ret = osAccountControlManager_->GetCreatedOsAccountNumFromDatabase(std::string(""), createdOsAccountNumByDefault);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(createdOsAccountNum, createdOsAccountNumByDefault);

    int64_t serialNumber = -1;
    ret = osAccountControlManager_->GetSerialNumberFromDatabase(storeID_, serialNumber);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(serialNumber, -1);

    int64_t serialNumberByDefault = -1;
    ret = osAccountControlManager_->GetSerialNumberFromDatabase(std::string(""), serialNumberByDefault);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(serialNumber, serialNumberByDefault);

    int id = -1;
    ret = osAccountControlManager_->GetMaxAllowCreateIdFromDatabase(storeID_, id);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(id, Constants::MAX_USER_ID);

    int idByDefault = -1;
    ret = osAccountControlManager_->GetMaxAllowCreateIdFromDatabase(std::string(""), idByDefault);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(id, idByDefault);

    std::vector<OsAccountInfo> osAccountList;
    ret = osAccountControlManager_->GetOsAccountListFromDatabase(storeID_, osAccountList);
    EXPECT_EQ(ret, ERR_OK);

    std::vector<OsAccountInfo> osAccountListByDefault;
    ret = osAccountControlManager_->GetOsAccountListFromDatabase(std::string(""), osAccountListByDefault);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(osAccountListByDefault.size(), osAccountList.size());

    if (osAccountListByDefault.size() == osAccountList.size()) {
        for (size_t i = 0; i < osAccountList.size(); ++i) {
            EXPECT_EQ(osAccountList[i].GetLocalId(), osAccountListByDefault[i].GetLocalId());
            EXPECT_EQ(osAccountList[i].GetSerialNumber(), osAccountListByDefault[i].GetSerialNumber());
            EXPECT_EQ(osAccountList[i].GetIsActived(), osAccountListByDefault[i].GetIsActived());
        }
    } else {
        std::cout << "Error: osAccountListByDefault.size() = " << osAccountListByDefault.size() << ", "
            << "osAccountList.size() = " << osAccountList.size() << std::endl;
    }
}

/**
 * @tc.name: OsAccountControlFileManagerTest022
 * @tc.desc: coverage GetValidAccountID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerCovTest022, TestSize.Level1)
{
    std::string dirName1;
    std::int32_t accountID;
    bool ret;
    ret = GetValidAccountID(dirName1, accountID);
    EXPECT_EQ(ret, false);
    // name length > MAX_USER_ID_LENGTH
    std::string dirName2(Constants::MAX_USER_ID_LENGTH + 1, 'a');
    ret = GetValidAccountID(dirName2, accountID);
    EXPECT_EQ(ret, false);


    std::string dirName3(Constants::MAX_USER_ID_LENGTH - 1, 'a');
    ret = GetValidAccountID(dirName3, accountID);
    EXPECT_EQ(ret, false);

    std::string dirName4(Constants::MAX_USER_ID_LENGTH - 1, '5');
    ret = GetValidAccountID(dirName4, accountID);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: OsAccountControlFileManagerCovTest023
 * @tc.desc: coverage RecoverAccountListJsonFile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerCovTest023, TestSize.Level1)
{
    osAccountControlManager_->RecoverAccountListJsonFile();
    bool ret = false;
    ret = osAccountControlManager_->accountFileOperator_->IsJsonFileReady(Constants::ACCOUNT_LIST_FILE_JSON_PATH);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: OsAccountControlFileManagerCovTest024
 * @tc.desc: coverage BuildAndSaveBaseOAConstraintsJsonFile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerCovTest024, TestSize.Level1)
{
    osAccountControlManager_->BuildAndSaveBaseOAConstraintsJsonFile();
    bool ret = false;
    ret = osAccountControlManager_->accountFileOperator_
        ->IsJsonFileReady(Constants::BASE_OSACCOUNT_CONSTRAINTS_JSON_PATH);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: OsAccountControlFileManagerCovTest025
 * @tc.desc: coverage BuildAndSaveGlobalOAConstraintsJsonFile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerCovTest025, TestSize.Level1)
{
    osAccountControlManager_->BuildAndSaveGlobalOAConstraintsJsonFile();
    bool ret = false;
    ret = osAccountControlManager_->accountFileOperator_
        ->IsJsonFileReady(Constants::GLOBAL_OSACCOUNT_CONSTRAINTS_JSON_PATH);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: OsAccountControlFileManagerCovTest026
 * @tc.desc: coverage BuildAndSaveSpecificOAConstraintsJsonFile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerCovTest026, TestSize.Level1)
{
    osAccountControlManager_->BuildAndSaveSpecificOAConstraintsJsonFile();
    bool ret = false;
    ret = osAccountControlManager_->accountFileOperator_
        ->IsJsonFileReady(Constants::SPECIFIC_OSACCOUNT_CONSTRAINTS_JSON_PATH);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: OsAccountControlFileManagerCovTest027
 * @tc.desc: coverage osAccountControlManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerCovTest027, TestSize.Level1)
{
    std::vector<std::string> constants;
    std::shared_ptr<OsAccountControlFileManager>  osAccountControlManager =
        std::make_shared<OsAccountControlFileManager>();
    ErrCode ret = osAccountControlManager->GetConstraintsByType(OsAccountType::ADMIN, constants);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_OS_FILE_GET_CONFIG_ERROR);
    bool isMultiAccount;
    ret = osAccountControlManager->GetIsMultiOsAccountEnable(isMultiAccount);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_OS_FILE_GET_CONFIG_ERROR);
    bool isAllowedCreateAdmin;
    ret = osAccountControlManager->IsAllowedCreateAdmin(isAllowedCreateAdmin);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_OS_FILE_GET_CONFIG_ERROR);
    std::vector<std::string> constraints;
    bool isExists;
    bool isOverSize;
    ret = osAccountControlManager->CheckConstraintsList(constraints, isExists, isOverSize);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_OS_FILE_GET_CONSTRAINTS_LITS_ERROR);
    EXPECT_EQ(isExists, true);
    EXPECT_EQ(isOverSize, false);

}

/**
 * @tc.name: OsAccountControlFileManagerCovTest028
 * @tc.desc: coverage GetConstraintsByType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerCovTest028, TestSize.Level1)
{
    std::vector<std::string> constants;
    osAccountControlManager_->Init();
    ErrCode ret = osAccountControlManager_->GetConstraintsByType(static_cast<OsAccountType>(INVALID_TYPE), constants);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_CONTROL_GET_TYPE_ERROR);
}

/**
 * @tc.name: OsAccountControlFileManagerCovTest029
 * @tc.desc: coverage UpdateBaseOAConstraints isAdd false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerCovTest029, TestSize.Level1)
{
    std::string idStr = "";
    std::vector<std::string> ConstraintStr = {};
    ErrCode ret = osAccountControlManager_->UpdateBaseOAConstraints(idStr, ConstraintStr, false);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: OsAccountControlFileManagerCovTest030
 * @tc.desc: coverage GetPhotoById with invalid id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerCovTest030, TestSize.Level1)
{
    int id = 0;
    std::string photo;
    ErrCode ret = osAccountControlManager_->GetPhotoById(id, photo);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_FILE_FIND_FILE_ERROR);
}
}  // namespace AccountSA
}  // namespace OHOS