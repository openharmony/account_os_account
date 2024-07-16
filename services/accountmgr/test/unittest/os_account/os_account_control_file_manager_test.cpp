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
#include <dirent.h>
#include <fstream>
#include <gtest/gtest.h>
#include <iostream>
#include <new>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "os_account_constants.h"
#define private public
#include "os_account_control_file_manager.h"
#include "os_account_file_operator.h"
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
const gid_t ACCOUNT_GID = 3058;
const uid_t ACCOUNT_UID = 3058;
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
    OsAccountControlFileManager *g_controlManager = new (std::nothrow) OsAccountControlFileManager();
}  // namespace
class OsAccountControlFileManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

public:
    std::string storeID_ = "os_account_info";
};

void OsAccountControlFileManagerTest::SetUpTestCase(void)
{
    ASSERT_NE(g_controlManager, nullptr);
    g_controlManager->Init();
}

void OsAccountControlFileManagerTest::TearDownTestCase(void)
{}

void OsAccountControlFileManagerTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void OsAccountControlFileManagerTest::TearDown(void)
{}

static int RenameFile(const std::string &src, const std::string &des)
{
    return rename(src.c_str(), des.c_str());
}

/**
 * @tc.name: OsAccountControlFileManagerTest001
 * @tc.desc: Test GetOsAccountList
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerTest001, TestSize.Level1)
{
    std::vector<OsAccountInfo> osAccountInfos;
    EXPECT_EQ(g_controlManager->GetOsAccountList(osAccountInfos), ERR_OK);
    const unsigned int size = 0;
    EXPECT_NE(osAccountInfos.size(), size);
}

#ifdef ENABLE_DEFAULT_ADMIN_NAME
/**
 * @tc.name: OsAccountControlFileManagerTest002
 * @tc.desc: Test GetOsAccountInfoById by valid data
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerTest002, TestSize.Level0)
{
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(g_controlManager->GetOsAccountInfoById(Constants::START_USER_ID, osAccountInfo), ERR_OK);
}
#endif // ENABLE_DEFAULT_ADMIN_NAME

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
    EXPECT_NE(g_controlManager->GetOsAccountInfoById(id, osAccountInfo), ERR_OK);
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
    EXPECT_EQ(g_controlManager->GetConstraintsByType(OsAccountType::ADMIN, constraints), ERR_OK);
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
    EXPECT_EQ(g_controlManager->GetConstraintsByType(OsAccountType::GUEST, constraints), ERR_OK);
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
    EXPECT_EQ(g_controlManager->GetSerialNumber(serialNumber1), ERR_OK);
    EXPECT_EQ(g_controlManager->GetSerialNumber(serialNumber2), ERR_OK);
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
    EXPECT_EQ(g_controlManager->IsOsAccountExists(Constants::START_USER_ID, isOsAccountExists), ERR_OK);
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
    EXPECT_EQ(g_controlManager->IsOsAccountExists(id, isOsAccountExists), ERR_OK);
    EXPECT_EQ(isOsAccountExists, false);
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
    EXPECT_EQ(g_controlManager->GetAllowCreateId(id), ERR_OK);
    EXPECT_NE(id, 0);
    bool isOsAccountExists = true;
    EXPECT_EQ(g_controlManager->IsOsAccountExists(id, isOsAccountExists), ERR_OK);
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
    g_controlManager->GetAllowCreateId(id);
    OsAccountInfo osAccountInfo(id, STRING_TEST_USER_NAME, OS_ACCOUNT_TYPE, STRING_TEST_USER_SHELLNUMBER);
    EXPECT_EQ(g_controlManager->InsertOsAccount(osAccountInfo), ERR_OK);
    bool isOsAccountExists = false;
    EXPECT_EQ(g_controlManager->IsOsAccountExists(id, isOsAccountExists), ERR_OK);
    EXPECT_NE(isOsAccountExists, false);
    g_controlManager->DelOsAccount(id);
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
    EXPECT_EQ(g_controlManager->InsertOsAccount(osAccountInfo),
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
    EXPECT_EQ(g_controlManager->InsertOsAccount(osAccountInfo),
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
    g_controlManager->GetAllowCreateId(id);
    OsAccountInfo osAccountInfo(id, STRING_TEST_USER_NAME, OS_ACCOUNT_TYPE, STRING_TEST_USER_SHELLNUMBER);
    EXPECT_EQ(g_controlManager->InsertOsAccount(osAccountInfo), ERR_OK);
    OsAccountInfo osAccountInfoTwo;
    g_controlManager->GetOsAccountInfoById(id, osAccountInfoTwo);
    EXPECT_EQ(osAccountInfoTwo.GetLocalName(), STRING_TEST_USER_NAME);
    EXPECT_EQ(g_controlManager->DelOsAccount(id), ERR_OK);
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
    EXPECT_NE(g_controlManager->DelOsAccount(id), ERR_OK);
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
    EXPECT_NE(g_controlManager->DelOsAccount(id), ERR_OK);
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
    g_controlManager->GetAllowCreateId(id);
    OsAccountInfo osAccountInfo(id, STRING_TEST_USER_NAME, OS_ACCOUNT_TYPE, STRING_TEST_USER_SHELLNUMBER);
    g_controlManager->InsertOsAccount(osAccountInfo);
    osAccountInfo.SetLocalName(STRING_TEST_USER_NAME_TWO);
    EXPECT_EQ(g_controlManager->UpdateOsAccount(osAccountInfo), ERR_OK);
    OsAccountInfo osAccountInfoTwo;
    g_controlManager->GetOsAccountInfoById(id, osAccountInfoTwo);
    EXPECT_EQ(osAccountInfoTwo.GetLocalName(), STRING_TEST_USER_NAME_TWO);
    g_controlManager->DelOsAccount(id);
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
    g_controlManager->GetAllowCreateId(id);
    OsAccountInfo osAccountInfo(id, STRING_TEST_USER_NAME, OS_ACCOUNT_TYPE, STRING_TEST_USER_SHELLNUMBER);
    g_controlManager->InsertOsAccount(osAccountInfo);
    EXPECT_EQ(g_controlManager->SetPhotoById(id, STRING_PHOTO), ERR_OK);
    std::string photo = Constants::USER_PHOTO_FILE_TXT_NAME;
    EXPECT_EQ(g_controlManager->GetPhotoById(id, photo), ERR_OK);
    EXPECT_EQ(photo, STRING_PHOTO);
    g_controlManager->DelOsAccount(id);
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
    g_controlManager->GetAllowCreateId(id);
    OsAccountInfo osAccountInfo(id, STRING_TEST_USER_NAME, OS_ACCOUNT_TYPE, STRING_TEST_USER_SHELLNUMBER);
    g_controlManager->InsertOsAccount(osAccountInfo);
    EXPECT_EQ(g_controlManager->SetPhotoById(id, STRING_ERR_PHOTO), ERR_OK);
    g_controlManager->DelOsAccount(id);
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
    ErrCode ret = g_controlManager->GetCreatedOsAccountNumFromDatabase(storeID_, createdOsAccountNum);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(createdOsAccountNum, 0);
    EXPECT_NE(createdOsAccountNum, -1);

    int64_t serialNumber = -1;
    ret = g_controlManager->GetSerialNumberFromDatabase(storeID_, serialNumber);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(serialNumber, -1);

    int id = -1;
    ret = g_controlManager->GetMaxAllowCreateIdFromDatabase(storeID_, id);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(id, Constants::MAX_USER_ID);

    std::vector<OsAccountInfo> osAccountList;
    ret = g_controlManager->GetOsAccountListFromDatabase(storeID_, osAccountList);
    EXPECT_EQ(ret, ERR_OK);

    for (uint32_t i = 0; i < osAccountList.size(); ++i) {
        int curID = osAccountList[i].GetLocalId();
        bool checkIdValid = (curID >= Constants::START_USER_ID);
        EXPECT_EQ(checkIdValid, true);

        OsAccountInfo curOsAccountInfo;
        ret = g_controlManager->GetOsAccountFromDatabase(storeID_, curID, curOsAccountInfo);
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
    ErrCode ret = g_controlManager->GetCreatedOsAccountNumFromDatabase(storeID_, createdOsAccountNum);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(createdOsAccountNum, -1);

    int createdOsAccountNumByDefault = -1;
    ret = g_controlManager->GetCreatedOsAccountNumFromDatabase(std::string(""), createdOsAccountNumByDefault);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(createdOsAccountNum, createdOsAccountNumByDefault);

    int64_t serialNumber = -1;
    ret = g_controlManager->GetSerialNumberFromDatabase(storeID_, serialNumber);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(serialNumber, -1);

    int64_t serialNumberByDefault = -1;
    ret = g_controlManager->GetSerialNumberFromDatabase(std::string(""), serialNumberByDefault);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(serialNumber, serialNumberByDefault);

    int id = -1;
    ret = g_controlManager->GetMaxAllowCreateIdFromDatabase(storeID_, id);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(id, Constants::MAX_USER_ID);

    int idByDefault = -1;
    ret = g_controlManager->GetMaxAllowCreateIdFromDatabase(std::string(""), idByDefault);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(id, idByDefault);

    std::vector<OsAccountInfo> osAccountList;
    ret = g_controlManager->GetOsAccountListFromDatabase(storeID_, osAccountList);
    EXPECT_EQ(ret, ERR_OK);

    std::vector<OsAccountInfo> osAccountListByDefault;
    ret = g_controlManager->GetOsAccountListFromDatabase(std::string(""), osAccountListByDefault);
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
    g_controlManager->accountFileOperator_->DeleteDirOrFile(Constants::ACCOUNT_LIST_FILE_JSON_PATH);
    g_controlManager->RecoverAccountListJsonFile();
    bool ret = false;
    ret = g_controlManager->accountFileOperator_->IsJsonFileReady(Constants::ACCOUNT_LIST_FILE_JSON_PATH);
    EXPECT_EQ(ret, true);
    // recover permission
    if (chmod(Constants::ACCOUNT_LIST_FILE_JSON_PATH.c_str(), S_IRUSR | S_IWUSR) != 0) {
        ACCOUNT_LOGE("OsAccountControlFileManagerCovTest023, chmod failed! errno %{public}d.", errno);
    }
    if (chown(Constants::ACCOUNT_LIST_FILE_JSON_PATH.c_str(), ACCOUNT_UID, ACCOUNT_GID) != 0) {
        ACCOUNT_LOGE("OsAccountControlFileManagerCovTest023, chown failed! errno %{public}d.", errno);
    }
}

/**
 * @tc.name: IsFromBaseOAConstraintsList_001
 * @tc.desc: coverage IsFromBaseOAConstraintsList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerTest, IsFromBaseOAConstraintsList_001, TestSize.Level1)
{
    bool isExist;
    RenameFile(Constants::BASE_OSACCOUNT_CONSTRAINTS_JSON_PATH,
        Constants::BASE_OSACCOUNT_CONSTRAINTS_JSON_PATH + "_blk");
    ErrCode ret = g_controlManager->IsFromBaseOAConstraintsList(
        INT_TEST_ERR_USER_ID, "invalid_constraint", isExist);
    EXPECT_NE(ret, ERR_OK);
    RenameFile(Constants::BASE_OSACCOUNT_CONSTRAINTS_JSON_PATH + "_blk",
        Constants::BASE_OSACCOUNT_CONSTRAINTS_JSON_PATH);
}

/**
 * @tc.name: IsFromBaseOAConstraintsList_002
 * @tc.desc: coverage IsFromBaseOAConstraintsList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerTest, IsFromBaseOAConstraintsList_002, TestSize.Level1)
{
    bool isExist;
    ErrCode ret = g_controlManager->IsFromBaseOAConstraintsList(
        100, "constraint.wifi", isExist);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(isExist, true);
}

/**
 * @tc.name: IsFromBaseOAConstraintsList_003
 * @tc.desc: coverage IsFromBaseOAConstraintsList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerTest, IsFromBaseOAConstraintsList_003, TestSize.Level1)
{
    bool isExist;
    RenameFile(Constants::BASE_OSACCOUNT_CONSTRAINTS_JSON_PATH,
        Constants::BASE_OSACCOUNT_CONSTRAINTS_JSON_PATH + "_blk");
    g_controlManager->BuildAndSaveBaseOAConstraintsJsonFile();
    ErrCode ret = g_controlManager->IsFromBaseOAConstraintsList(
        100, "constraint.wifi", isExist);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(isExist, true);
    RenameFile(Constants::BASE_OSACCOUNT_CONSTRAINTS_JSON_PATH + "_blk",
        Constants::BASE_OSACCOUNT_CONSTRAINTS_JSON_PATH);
}

/**
 * @tc.name: RemoveOAConstraintsInfo_001
 * @tc.desc: coverage RemoveOAConstraintsInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerTest, RemoveOAConstraintsInfo_001, TestSize.Level1)
{
    RenameFile(Constants::BASE_OSACCOUNT_CONSTRAINTS_JSON_PATH,
        Constants::BASE_OSACCOUNT_CONSTRAINTS_JSON_PATH + "_blk");
    ErrCode ret = g_controlManager->RemoveOAConstraintsInfo(INT_TEST_ERR_USER_ID);
    EXPECT_NE(ret, ERR_OK);
    RenameFile(Constants::BASE_OSACCOUNT_CONSTRAINTS_JSON_PATH + "_blk",
        Constants::BASE_OSACCOUNT_CONSTRAINTS_JSON_PATH);
}

/**
 * @tc.name: IsFromGlobalOAConstraintsList_001
 * @tc.desc: coverage IsFromGlobalOAConstraintsList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerTest, IsFromGlobalOAConstraintsList_001, TestSize.Level1)
{
    std::vector<ConstraintSourceTypeInfo> globalSourceList;
    RenameFile(Constants::GLOBAL_OSACCOUNT_CONSTRAINTS_JSON_PATH,
        Constants::GLOBAL_OSACCOUNT_CONSTRAINTS_JSON_PATH + "_blk");
    ErrCode ret = g_controlManager->IsFromGlobalOAConstraintsList(
        INT_TEST_ERR_USER_ID, 0, "invalid_constraint", globalSourceList);
    EXPECT_NE(ret, ERR_OK);
    RenameFile(Constants::GLOBAL_OSACCOUNT_CONSTRAINTS_JSON_PATH + "_blk",
        Constants::GLOBAL_OSACCOUNT_CONSTRAINTS_JSON_PATH);
}

/**
 * @tc.name: IsFromSpecificOAConstraintsList_001
 * @tc.desc: coverage IsFromSpecificOAConstraintsList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerTest, IsFromSpecificOAConstraintsList_001, TestSize.Level1)
{
    std::vector<ConstraintSourceTypeInfo> specificSourceList;
    RenameFile(Constants::SPECIFIC_OSACCOUNT_CONSTRAINTS_JSON_PATH,
        Constants::SPECIFIC_OSACCOUNT_CONSTRAINTS_JSON_PATH + "_blk");
    ErrCode ret = g_controlManager->IsFromSpecificOAConstraintsList(
        INT_TEST_ERR_USER_ID, 0, "invalid_constraint", specificSourceList);
    EXPECT_NE(ret, ERR_OK);
    RenameFile(Constants::SPECIFIC_OSACCOUNT_CONSTRAINTS_JSON_PATH + "_blk",
        Constants::SPECIFIC_OSACCOUNT_CONSTRAINTS_JSON_PATH);
}

/**
 * @tc.name: OsAccountControlFileManagerCovTest024
 * @tc.desc: coverage BuildAndSaveBaseOAConstraintsJsonFile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerCovTest024, TestSize.Level1)
{
    g_controlManager->BuildAndSaveBaseOAConstraintsJsonFile();
    bool ret = false;
    ret = g_controlManager->accountFileOperator_
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
    g_controlManager->BuildAndSaveGlobalOAConstraintsJsonFile();
    bool ret = false;
    ret = g_controlManager->accountFileOperator_
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
    g_controlManager->BuildAndSaveSpecificOAConstraintsJsonFile();
    bool ret = false;
    ret = g_controlManager->accountFileOperator_
        ->IsJsonFileReady(Constants::SPECIFIC_OSACCOUNT_CONSTRAINTS_JSON_PATH);
    EXPECT_EQ(ret, true);
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
    ErrCode ret = g_controlManager->GetConstraintsByType(static_cast<OsAccountType>(INVALID_TYPE), constants);
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
    ErrCode ret = g_controlManager->UpdateBaseOAConstraints(idStr, ConstraintStr, false);
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
    ErrCode ret = g_controlManager->GetPhotoById(id, photo);
    EXPECT_EQ(ret, ERR_OK);
}
}  // namespace AccountSA
}  // namespace OHOS