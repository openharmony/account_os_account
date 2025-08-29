/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
#include <gtest/hwext/gtest-multithread.h>
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
#include "account_file_watcher_manager.h"
#undef private

namespace OHOS {
namespace AccountSA {
using namespace testing;
using namespace testing::mt;
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
#ifdef ENABLE_U1_ACCOUNT
const char SYSTEM_ACCOUNTS_CONFIG[] = "systemAccounts";
const char U1_CONFIG[] = "1";
const char SYSTEM_ACCOUNT_NAME[] = "name";
const char SYSTEM_ACCOUNT_TYPE[] = "type";
#endif // ENABLE_U1_ACCOUNT
const std::string TEST_FILE_PATH = "/data/service/el1/public/account/test";
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
class OsAccountControlFileManagerUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

public:
    std::string storeID_ = "os_account_info";
};

void OsAccountControlFileManagerUnitTest::SetUpTestCase(void)
{
    ASSERT_NE(g_controlManager, nullptr);
    g_controlManager->Init();
}

void OsAccountControlFileManagerUnitTest::TearDownTestCase(void)
{
    std::string cmd = "rm -rf " + TEST_FILE_PATH + "*";
    system(cmd.c_str());
}


void OsAccountControlFileManagerUnitTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void OsAccountControlFileManagerUnitTest::TearDown(void)
{}

static int RenameFile(const std::string &src, const std::string &des)
{
    return rename(src.c_str(), des.c_str());
}

void GetOsAccountFromDatabaseTest()
{
    int32_t i = 100;
    while (i--) {
        OsAccountInfo osAccountInfo;
        EXPECT_NE(g_controlManager->GetOsAccountFromDatabase(
            "155000", Constants::START_USER_ID, osAccountInfo), ERR_OK);
    }
}

/**
 * @tc.name: OsAccountControlFileManagerTest001
 * @tc.desc: Test GetOsAccountList
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountControlFileManagerUnitTest, OsAccountControlFileManagerTest001, TestSize.Level1)
{
    std::vector<OsAccountInfo> osAccountInfos;
    EXPECT_EQ(g_controlManager->GetOsAccountList(osAccountInfos), ERR_OK);
    const unsigned int size = 0;
    EXPECT_EQ(osAccountInfos.size(), size);
}

#ifdef ENABLE_DEFAULT_ADMIN_NAME
/**
 * @tc.name: OsAccountControlFileManagerTest002
 * @tc.desc: Test GetOsAccountInfoById by valid data
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountControlFileManagerUnitTest, OsAccountControlFileManagerTest002, TestSize.Level3)
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
HWTEST_F(OsAccountControlFileManagerUnitTest, OsAccountControlFileManagerTest003, TestSize.Level1)
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
HWTEST_F(OsAccountControlFileManagerUnitTest, OsAccountControlFileManagerTest004, TestSize.Level1)
{
    std::vector<std::string> constraints;
    EXPECT_EQ(g_controlManager->GetConstraintsByType(OsAccountType::ADMIN, constraints), ERR_OK);
    EXPECT_NE(0, constraints.size());
}

/**
 * @tc.name: OsAccountControlFileManagerTest005
 * @tc.desc: Test GetConstraintsByType by other type
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountControlFileManagerUnitTest, OsAccountControlFileManagerTest005, TestSize.Level1)
{
    std::vector<std::string> constraints;
    EXPECT_EQ(g_controlManager->GetConstraintsByType(OsAccountType::GUEST, constraints), ERR_OK);
    EXPECT_NE(0, constraints.size());
}

/**
 * @tc.name: OsAccountControlFileManagerTest006
 * @tc.desc: Test GetSerialNumber
 * @tc.type: FUNC
 * @tc.require: SR000GGV0U
 */
HWTEST_F(OsAccountControlFileManagerUnitTest, OsAccountControlFileManagerTest006, TestSize.Level1)
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
HWTEST_F(OsAccountControlFileManagerUnitTest, OsAccountControlFileManagerTest007, TestSize.Level1)
{
    bool isOsAccountExists = false;
    int32_t id = 0;
    g_controlManager->GetAllowCreateId(id);
    OsAccountInfo osAccountInfo(id, STRING_TEST_USER_NAME, OS_ACCOUNT_TYPE, STRING_TEST_USER_SHELLNUMBER);
    EXPECT_EQ(g_controlManager->InsertOsAccount(osAccountInfo), ERR_OK);
    EXPECT_EQ(g_controlManager->IsOsAccountExists(id, isOsAccountExists), ERR_OK);
    EXPECT_EQ(isOsAccountExists, true);
    g_controlManager->DelOsAccount(id);
}

/**
 * @tc.name: OsAccountControlFileManagerTest008
 * @tc.desc: Test IsOsAccountExists
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountControlFileManagerUnitTest, OsAccountControlFileManagerTest008, TestSize.Level1)
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
HWTEST_F(OsAccountControlFileManagerUnitTest, OsAccountControlFileManagerTest010, TestSize.Level1)
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
HWTEST_F(OsAccountControlFileManagerUnitTest, OsAccountControlFileManagerTest011, TestSize.Level1)
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
 * @tc.name: OsAccountControlFileManagerTest013
 * @tc.desc: Test InsertOsAccount with invalid data
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountControlFileManagerUnitTest, OsAccountControlFileManagerTest013, TestSize.Level1)
{
    OsAccountInfo osAccountInfo(
        Constants::START_USER_ID, STRING_TEST_USER_NAME, OS_ACCOUNT_TYPE, STRING_TEST_USER_SHELLNUMBER);
    EXPECT_EQ(g_controlManager->InsertOsAccount(osAccountInfo), ERR_OK);
    EXPECT_EQ(g_controlManager->InsertOsAccount(osAccountInfo), ERR_OSACCOUNT_SERVICE_CONTROL_INSERT_FILE_EXISTS_ERROR);
    g_controlManager->DelOsAccount(Constants::START_USER_ID);
}

/**
 * @tc.name: OsAccountControlFileManagerTest014
 * @tc.desc: Test DelOsAccount
 * @tc.type: FUNC
 * @tc.require: SR000GGV0U
 */
HWTEST_F(OsAccountControlFileManagerUnitTest, OsAccountControlFileManagerTest014, TestSize.Level3)
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
HWTEST_F(OsAccountControlFileManagerUnitTest, OsAccountControlFileManagerTest015, TestSize.Level1)
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
HWTEST_F(OsAccountControlFileManagerUnitTest, OsAccountControlFileManagerTest016, TestSize.Level1)
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
HWTEST_F(OsAccountControlFileManagerUnitTest, OsAccountControlFileManagerTest017, TestSize.Level3)
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
HWTEST_F(OsAccountControlFileManagerUnitTest, OsAccountControlFileManagerTest018, TestSize.Level1)
{
    int id = 0;
    g_controlManager->GetAllowCreateId(id);
    OsAccountInfo osAccountInfo(id, STRING_TEST_USER_NAME, OS_ACCOUNT_TYPE, STRING_TEST_USER_SHELLNUMBER);
    osAccountInfo.SetPhoto(Constants::USER_PHOTO_FILE_TXT_NAME);
    g_controlManager->InsertOsAccount(osAccountInfo);
    EXPECT_EQ(g_controlManager->SetPhotoById(id, STRING_PHOTO), ERR_OK);
    std::string photo = Constants::USER_PHOTO_FILE_TXT_NAME;
    EXPECT_EQ(g_controlManager->GetPhotoById(id, photo), ERR_OK);
    EXPECT_EQ(photo, STRING_PHOTO);

    std::vector<OsAccountInfo> osAccountInfos;
    EXPECT_EQ(g_controlManager->GetOsAccountList(osAccountInfos), ERR_OK);
    for (auto info: osAccountInfos) {
        if (info.GetLocalId() == id) {
            EXPECT_EQ(info.GetPhoto(), STRING_PHOTO);
        }
    }
    g_controlManager->DelOsAccount(id);
}

/**
 * @tc.name: OsAccountControlFileManagerTest019
 * @tc.desc: Test SetPhotoById
 * @tc.type: FUNC
 * @tc.require: SR000GGVFI
 */
HWTEST_F(OsAccountControlFileManagerUnitTest, OsAccountControlFileManagerTest019, TestSize.Level1)
{
    int id = 0;
    g_controlManager->GetAllowCreateId(id);
    OsAccountInfo osAccountInfo(id, STRING_TEST_USER_NAME, OS_ACCOUNT_TYPE, STRING_TEST_USER_SHELLNUMBER);
    g_controlManager->InsertOsAccount(osAccountInfo);
    EXPECT_EQ(g_controlManager->SetPhotoById(id, STRING_ERR_PHOTO), ERR_OK);
    g_controlManager->DelOsAccount(id);
}

#if defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)
/**
 * @tc.name: OsAccountControlFileManagerTest020
 * @tc.desc: GetCreatedOsAccountNumFromDatabase
 * @tc.type: FUNC
 * @tc.require: SR000GGVFK
 */
HWTEST_F(OsAccountControlFileManagerUnitTest, OsAccountControlFileManagerTest020, TestSize.Level1)
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
HWTEST_F(OsAccountControlFileManagerUnitTest, OsAccountControlFileManagerTest021, TestSize.Level1)
{
    int createdOsAccountNum = -1;
    ErrCode ret = g_controlManager->GetCreatedOsAccountNumFromDatabase(storeID_, createdOsAccountNum);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(createdOsAccountNum, -1);

    int createdOsAccountNumByDefault = -2;
    ret = g_controlManager->GetCreatedOsAccountNumFromDatabase(std::string(""), createdOsAccountNumByDefault);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(createdOsAccountNum, createdOsAccountNumByDefault);

    int64_t serialNumber = -1;
    ret = g_controlManager->GetSerialNumberFromDatabase(storeID_, serialNumber);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(serialNumber, -1);

    int64_t serialNumberByDefault = -2;
    ret = g_controlManager->GetSerialNumberFromDatabase(std::string(""), serialNumberByDefault);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(serialNumber, serialNumberByDefault);

    int id = -1;
    ret = g_controlManager->GetMaxAllowCreateIdFromDatabase(storeID_, id);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(id, Constants::MAX_USER_ID);

    int idByDefault = -2;
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
#endif // defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)

/**
 * @tc.name: OsAccountControlFileManagerTest022
 * @tc.desc: coverage GetValidAccountID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerUnitTest, OsAccountControlFileManagerCovTest022, TestSize.Level1)
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
HWTEST_F(OsAccountControlFileManagerUnitTest, OsAccountControlFileManagerCovTest023, TestSize.Level1)
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
 * @tc.name: OsAccountControlFileManagerTest024
 * @tc.desc: Test multiple thread get osaccount from database
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerUnitTest, OsAccountControlFileManagerTest024, TestSize.Level1)
{
    GTEST_RUN_TASK(GetOsAccountFromDatabaseTest);
}

/**
 * @tc.name: OsAccountControlFileManagerTest025
 * @tc.desc: Test GetAllowCreateId when ID range is full
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerUnitTest, OsAccountControlFileManagerTest025, TestSize.Level1)
{
    std::string backupPath = Constants::ACCOUNT_LIST_FILE_JSON_PATH + ".backup";
    std::string accountListContent;
    g_controlManager->accountFileOperator_->GetFileContentByPath(
        Constants::ACCOUNT_LIST_FILE_JSON_PATH, accountListContent);
    g_controlManager->accountFileOperator_->InputFileByPathAndContent(backupPath, accountListContent);
    
    CJsonUnique fullAccountListJson = CreateJson();
    std::vector<std::string> fullAccountIdList;
    
    for (int32_t i = Constants::START_USER_ID + 1; i <= Constants::MAX_CREATABLE_USER_ID; i++) {
        fullAccountIdList.push_back(std::to_string(i));
    }
    
    AddVectorStringToJson(fullAccountListJson, Constants::ACCOUNT_LIST, fullAccountIdList);
    AddIntToJson(fullAccountListJson, "nextLocalId", Constants::MAX_CREATABLE_USER_ID + 1);
    AddIntToJson(fullAccountListJson, Constants::COUNT_ACCOUNT_NUM, static_cast<int>(fullAccountIdList.size()));
    AddInt64ToJson(fullAccountListJson, Constants::SERIAL_NUMBER_NUM, Constants::MAX_CREATABLE_USER_ID + 1);
    AddIntToJson(fullAccountListJson, Constants::MAX_ALLOW_CREATE_ACCOUNT_ID, Constants::MAX_CREATABLE_USER_ID);
    
    std::string fullAccountListStr = PackJsonToString(fullAccountListJson);
    EXPECT_EQ(g_controlManager->accountFileOperator_->InputFileByPathAndContent(
        Constants::ACCOUNT_LIST_FILE_JSON_PATH, fullAccountListStr), ERR_OK);
    
    int id = 0;
    ErrCode result = g_controlManager->GetAllowCreateId(id);
    
    EXPECT_EQ(result, ERR_OSACCOUNT_SERVICE_CONTROL_MAX_CAN_CREATE_ERROR);
    
    EXPECT_GT(id, Constants::MAX_CREATABLE_USER_ID);
    
    g_controlManager->accountFileOperator_->GetFileContentByPath(backupPath, accountListContent);
    g_controlManager->accountFileOperator_->InputFileByPathAndContent(
        Constants::ACCOUNT_LIST_FILE_JSON_PATH, accountListContent);
    g_controlManager->accountFileOperator_->DeleteDirOrFile(backupPath);
}

/**
 * @tc.name: IsFromBaseOAConstraintsList_001
 * @tc.desc: coverage IsFromBaseOAConstraintsList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerUnitTest, IsFromBaseOAConstraintsList_001, TestSize.Level1)
{
    bool isExist = true;
    ErrCode ret = g_controlManager->IsFromBaseOAConstraintsList(
        INT_TEST_ERR_USER_ID, "invalid_constraint", isExist);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(isExist, false);
}

/**
 * @tc.name: IsFromBaseOAConstraintsList_002
 * @tc.desc: coverage IsFromBaseOAConstraintsList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerUnitTest, IsFromBaseOAConstraintsList_002, TestSize.Level1)
{
    bool isExist = false;
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
HWTEST_F(OsAccountControlFileManagerUnitTest, IsFromBaseOAConstraintsList_003, TestSize.Level1)
{
    bool isExist = false;
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
HWTEST_F(OsAccountControlFileManagerUnitTest, RemoveOAConstraintsInfo_001, TestSize.Level1)
{
    std::string res1;
    EXPECT_EQ(ERR_OK, g_controlManager->accountFileOperator_
        ->GetFileContentByPath(Constants::BASE_OSACCOUNT_CONSTRAINTS_JSON_PATH, res1));
    EXPECT_EQ(ERR_OK, g_controlManager->RemoveOAConstraintsInfo(INT_TEST_ERR_USER_ID));
    std::string res2;
    EXPECT_EQ(ERR_OK, g_controlManager->accountFileOperator_
        ->GetFileContentByPath(Constants::BASE_OSACCOUNT_CONSTRAINTS_JSON_PATH, res2));
    EXPECT_EQ(res1, res2);
}

/**
 * @tc.name: IsFromGlobalOAConstraintsList_001
 * @tc.desc: coverage IsFromGlobalOAConstraintsList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerUnitTest, IsFromGlobalOAConstraintsList_001, TestSize.Level1)
{
    std::vector<ConstraintSourceTypeInfo> globalSourceList;
    ErrCode ret = g_controlManager->IsFromGlobalOAConstraintsList(
        INT_TEST_ERR_USER_ID, 0, "invalid_constraint", globalSourceList);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(globalSourceList.empty());
}

/**
 * @tc.name: IsFromSpecificOAConstraintsList_001
 * @tc.desc: coverage IsFromSpecificOAConstraintsList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerUnitTest, IsFromSpecificOAConstraintsList_001, TestSize.Level1)
{
    std::vector<ConstraintSourceTypeInfo> specificSourceList;
    ErrCode ret = g_controlManager->IsFromSpecificOAConstraintsList(
        INT_TEST_ERR_USER_ID, 0, "invalid_constraint", specificSourceList);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(specificSourceList.empty());
}

/**
 * @tc.name: OsAccountControlFileManagerCovTest024
 * @tc.desc: coverage BuildAndSaveBaseOAConstraintsJsonFile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerUnitTest, OsAccountControlFileManagerCovTest024, TestSize.Level1)
{
    g_controlManager->BuildAndSaveBaseOAConstraintsJsonFile();
    EXPECT_TRUE(g_controlManager->accountFileOperator_
        ->IsJsonFileReady(Constants::BASE_OSACCOUNT_CONSTRAINTS_JSON_PATH));

    std::string res;
    EXPECT_EQ(ERR_OK, g_controlManager->accountFileOperator_
        ->GetFileContentByPath(Constants::BASE_OSACCOUNT_CONSTRAINTS_JSON_PATH, res));
    EXPECT_TRUE(res.find("100") != std::string::npos);
}

/**
 * @tc.name: OsAccountControlFileManagerCovTest025
 * @tc.desc: coverage BuildAndSaveGlobalOAConstraintsJsonFile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerUnitTest, OsAccountControlFileManagerCovTest025, TestSize.Level1)
{
    g_controlManager->BuildAndSaveGlobalOAConstraintsJsonFile();
    EXPECT_TRUE(g_controlManager->accountFileOperator_
        ->IsJsonFileReady(Constants::GLOBAL_OSACCOUNT_CONSTRAINTS_JSON_PATH));
    std::string res;
    EXPECT_EQ(ERR_OK, g_controlManager->accountFileOperator_
        ->GetFileContentByPath(Constants::GLOBAL_OSACCOUNT_CONSTRAINTS_JSON_PATH, res));
    EXPECT_TRUE(res.find("deviceOwnerId") != std::string::npos);
}

/**
 * @tc.name: OsAccountControlFileManagerCovTest026
 * @tc.desc: coverage BuildAndSaveSpecificOAConstraintsJsonFile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerUnitTest, OsAccountControlFileManagerCovTest026, TestSize.Level1)
{
    g_controlManager->BuildAndSaveSpecificOAConstraintsJsonFile();
    EXPECT_TRUE(g_controlManager->accountFileOperator_
        ->IsJsonFileReady(Constants::SPECIFIC_OSACCOUNT_CONSTRAINTS_JSON_PATH));
    std::string res;
    EXPECT_EQ(ERR_OK, g_controlManager->accountFileOperator_
        ->GetFileContentByPath(Constants::SPECIFIC_OSACCOUNT_CONSTRAINTS_JSON_PATH, res));
    EXPECT_TRUE(res.find("allSpecificConstraints") != std::string::npos);
}

/**
 * @tc.name: OsAccountControlFileManagerCovTest028
 * @tc.desc: coverage GetConstraintsByType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerUnitTest, OsAccountControlFileManagerCovTest028, TestSize.Level1)
{
    std::vector<std::string> constraints;
    ErrCode ret = g_controlManager->GetConstraintsByType(static_cast<OsAccountType>(INVALID_TYPE), constraints);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(constraints.empty());
}

/**
 * @tc.name: OsAccountControlFileManagerCovTest029
 * @tc.desc: coverage UpdateBaseOAConstraints isAdd false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerUnitTest, OsAccountControlFileManagerCovTest029, TestSize.Level1)
{
    std::string idStr = "";
    std::vector<std::string> ConstraintStr = {};
    ErrCode ret = g_controlManager->UpdateBaseOAConstraints(idStr, ConstraintStr, false);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(ConstraintStr.empty());
}

/**
 * @tc.name: OsAccountControlFileManagerCovTest030
 * @tc.desc: coverage GetPhotoById with invalid id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerUnitTest, OsAccountControlFileManagerCovTest030, TestSize.Level1)
{
    int id = 0;
    std::string photo;
    ErrCode ret = g_controlManager->GetPhotoById(id, photo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(photo.empty());
}

#ifdef ENABLE_U1_ACCOUNT
/**
 * @tc.name: GetU1Config001
 * @tc.desc: coverage GetU1Config
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerUnitTest, GetU1Config001, TestSize.Level2)
{
    auto json = CreateJson();
    auto u1Json = CreateJson();
    auto systemJson = CreateJson();
    OsAccountConfig config;
    g_controlManager->GetU1Config(json, config);
    EXPECT_EQ(config.isU1Enable, false);
    AddStringToJson(u1Json, SYSTEM_ACCOUNT_NAME, STRING_TEST_USER_NAME);
    g_controlManager->GetU1Config(json, config);
    EXPECT_EQ(config.isU1Enable, false);
    AddObjToJson(systemJson, U1_CONFIG, u1Json);
    AddObjToJson(json, SYSTEM_ACCOUNTS_CONFIG, systemJson);
    g_controlManager->GetU1Config(json, config);
    EXPECT_EQ(config.isU1Enable, true);
    std::string errName(2000, '1');
    AddStringToJson(u1Json, SYSTEM_ACCOUNT_NAME, errName);
    AddObjToJson(systemJson, U1_CONFIG, u1Json);
    AddObjToJson(json, SYSTEM_ACCOUNTS_CONFIG, systemJson);
    g_controlManager->GetU1Config(json, config);
    EXPECT_EQ(config.isU1Enable, true);
    AddIntToJson(u1Json, SYSTEM_ACCOUNT_TYPE, static_cast<int32_t>(OsAccountType::ADMIN));
    AddObjToJson(systemJson, U1_CONFIG, u1Json);
    AddObjToJson(json, SYSTEM_ACCOUNTS_CONFIG, systemJson);
    g_controlManager->GetU1Config(json, config);
    EXPECT_EQ(config.isU1Enable, true);
    AddIntToJson(u1Json, SYSTEM_ACCOUNT_TYPE, static_cast<int32_t>(OsAccountType::NORMAL));
    AddObjToJson(systemJson, U1_CONFIG, u1Json);
    AddObjToJson(json, SYSTEM_ACCOUNTS_CONFIG, systemJson);
    g_controlManager->GetU1Config(json, config);
    EXPECT_EQ(config.isU1Enable, true);
    AddIntToJson(u1Json, SYSTEM_ACCOUNT_TYPE, static_cast<int32_t>(OsAccountType::GUEST));
    AddObjToJson(systemJson, U1_CONFIG, u1Json);
    AddObjToJson(json, SYSTEM_ACCOUNTS_CONFIG, systemJson);
    g_controlManager->GetU1Config(json, config);
    EXPECT_EQ(config.isU1Enable, true);
    AddIntToJson(u1Json, SYSTEM_ACCOUNT_TYPE, static_cast<int32_t>(OsAccountType::PRIVATE));
    AddObjToJson(systemJson, U1_CONFIG, u1Json);
    AddObjToJson(json, SYSTEM_ACCOUNTS_CONFIG, systemJson);
    g_controlManager->GetU1Config(json, config);
    EXPECT_EQ(config.isU1Enable, true);
    AddIntToJson(u1Json, SYSTEM_ACCOUNT_TYPE, static_cast<int32_t>(OsAccountType::END));
    AddObjToJson(systemJson, U1_CONFIG, u1Json);
    AddObjToJson(json, SYSTEM_ACCOUNTS_CONFIG, systemJson);
    g_controlManager->GetU1Config(json, config);
    EXPECT_EQ(config.isU1Enable, true);
}
#endif // ENABLE_U1_ACCOUNT

#ifdef ENABLE_FILE_WATCHER
/**
 * @tc.name: GetWrongAccountInfoDigestFromFile
 * @tc.desc: coverage GetAccountInfoDigestFromFile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerUnitTest, GetWrongAccountInfoDigestFromFile, TestSize.Level1)
{
    std::string invalidDigestJson = R"({
        "/test/path": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    })";
    auto fileOperator = std::make_shared<AccountFileOperator>();
    fileOperator->CreateDir("/data/service/el1/public/account");
    EXPECT_EQ(fileOperator->InputFileByPathAndContent(
        Constants::ACCOUNT_INFO_DIGEST_FILE_PATH, invalidDigestJson), ERR_OK);
    
    uint8_t digest[32] = {0};
    uint32_t size = 32;
    AccountFileWatcherMgr &fileWatcherMgr = AccountFileWatcherMgr::GetInstance();
    ErrCode result = fileWatcherMgr.GetAccountInfoDigestFromFile(
        Constants::ACCOUNT_INFO_DIGEST_FILE_PATH, digest, size);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_DUMP_JSON_ERROR);
    fileOperator->DeleteDirOrFile(Constants::ACCOUNT_INFO_DIGEST_FILE_PATH);
}
#endif // ENABLE_FILE_WATCHER

/**
 * @tc.name: OTACompatibilityTest001_ReadOldFormatDefaultActivatedAccount
 * @tc.desc: Test reading old format (integer) default activated account data and converting to new format
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerUnitTest,
    OTACompatibilityTest001_ReadOldFormatDefaultActivatedAccount, TestSize.Level1)
{
    // Create old format account list file: "DefaultActivatedAccountID": 100
    std::string oldFormatAccountList = R"({
        "AccountList": ["100"],
        "CountAccountNum": 1,
        "IsSerialNumberFull": false,
        "NextLocalId": 101,
        "SerialNumber": 1,
        "DefaultActivatedAccountID": 100
    })";
    
    auto fileOperator = std::make_shared<AccountFileOperator>();
    fileOperator->CreateDir("/data/service/el1/public/account");
    EXPECT_EQ(fileOperator->InputFileByPathAndContent(
        Constants::ACCOUNT_LIST_FILE_JSON_PATH, oldFormatAccountList), ERR_OK);
    
    // Test reading old format data with new code
    int32_t id = -1;
    ErrCode result = g_controlManager->GetDefaultActivatedOsAccount(Constants::DEFAULT_DISPLAY_ID, id);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(id, 100);
    
    // Test reading for non-default display should fail for old format
    int32_t nonDefaultId = -1;
    result = g_controlManager->GetDefaultActivatedOsAccount(1, nonDefaultId);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_DISPLAY_ID_NOT_EXIST_ERROR);
    
    // Test GetAllDefaultActivatedOsAccounts with old format
    std::map<uint64_t, int32_t> ids;
    result = g_controlManager->GetAllDefaultActivatedOsAccounts(ids);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(ids.size(), 1);
    EXPECT_EQ(ids[Constants::DEFAULT_DISPLAY_ID], 100);
    
    // Clean up
    fileOperator->DeleteDirOrFile(Constants::ACCOUNT_LIST_FILE_JSON_PATH);
}

/**
 * @tc.name: OTACompatibilityTest002_UpgradeOldFormatToNewFormat
 * @tc.desc: Test upgrading old format to new format when setting default activated account
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerUnitTest, OTACompatibilityTest002_UpgradeOldFormatToNewFormat, TestSize.Level1)
{
    // Create old format account list file: "DefaultActivatedAccountID": 100
    std::string oldFormatAccountList = R"({
        "AccountList": ["100"],
        "CountAccountNum": 1,
        "IsSerialNumberFull": false,
        "NextLocalId": 101,
        "SerialNumber": 1,
        "DefaultActivatedAccountID": 100
    })";
    
    auto fileOperator = std::make_shared<AccountFileOperator>();
    fileOperator->CreateDir("/data/service/el1/public/account");
    EXPECT_EQ(fileOperator->InputFileByPathAndContent(
        Constants::ACCOUNT_LIST_FILE_JSON_PATH, oldFormatAccountList), ERR_OK);
    
    // Set new account for default display (should upgrade format)
    ErrCode result = g_controlManager->SetDefaultActivatedOsAccount(Constants::DEFAULT_DISPLAY_ID, 101);
    EXPECT_EQ(result, ERR_OK);
    
    // Verify the old data is preserved and new data is added
    int32_t defaultId = -1;
    result = g_controlManager->GetDefaultActivatedOsAccount(Constants::DEFAULT_DISPLAY_ID, defaultId);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(defaultId, 101);
    
    // Set account for another display
    result = g_controlManager->SetDefaultActivatedOsAccount(1, 102);
    EXPECT_EQ(result, ERR_OK);
    
    // Verify both displays have correct accounts
    std::map<uint64_t, int32_t> ids;
    result = g_controlManager->GetAllDefaultActivatedOsAccounts(ids);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(ids.size(), 2);
    EXPECT_EQ(ids[Constants::DEFAULT_DISPLAY_ID], 101);
    EXPECT_EQ(ids[1], 102);
    
    // Verify the file now has new format
    std::string fileContent;
    result = fileOperator->GetFileContentByPath(Constants::ACCOUNT_LIST_FILE_JSON_PATH, fileContent);
    EXPECT_EQ(result, ERR_OK);
    
    // Check that the content contains object format
    EXPECT_TRUE(fileContent.find("\"DefaultActivatedAccountID\":{") != std::string::npos);
    EXPECT_TRUE(fileContent.find("\"0\":101") != std::string::npos);
    EXPECT_TRUE(fileContent.find("\"1\":102") != std::string::npos);
    
    // Clean up
    fileOperator->DeleteDirOrFile(Constants::ACCOUNT_LIST_FILE_JSON_PATH);
}
}  // namespace AccountSA
}  // namespace OHOS
