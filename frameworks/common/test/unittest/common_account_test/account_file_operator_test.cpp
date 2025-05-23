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

#include <cstdint>
#include <iosfwd>
#include <fstream>
#include <pthread.h>
#include <string>
#include <gtest/gtest.h>
#include "gtest/gtest-message.h"
#include "gtest/gtest-test-part.h"
#include "gtest/hwext/gtest-ext.h"
#include "gtest/hwext/gtest-tag.h"
#include <gtest/hwext/gtest-multithread.h>
#include "account_log_wrapper.h"
#define private public
#define protected public
#include "account_file_operator.h"
#undef protected
#undef private

using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS;

namespace {
const std::string TEST_FILE_PATH = "/data/service/el1/public/account/test";
};

class AccountFileOperatorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AccountFileOperatorTest::SetUpTestCase() {}

void AccountFileOperatorTest::TearDownTestCase()
{
    std::string cmd = "rm -rf " + TEST_FILE_PATH + "*";
    system(cmd.c_str());
}

void AccountFileOperatorTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());

    auto accountFileOperator_ = std::make_shared<AccountFileOperator>();
    accountFileOperator_->DeleteFile(TEST_FILE_PATH);
    accountFileOperator_->DeleteFile(FileTransaction::GetTempFilePath(TEST_FILE_PATH));
}

void AccountFileOperatorTest::TearDown()
{
    auto accountFileOperator_ = std::make_shared<AccountFileOperator>();
    accountFileOperator_->DeleteFile(TEST_FILE_PATH);
    accountFileOperator_->DeleteFile(FileTransaction::GetTempFilePath(TEST_FILE_PATH));
}

/**
 * @tc.name: AccountFileOperator001
 * @tc.desc: Test invalid path
 * @tc.type: FUNC
 * @tc.require: issueI5RWXN
 */
HWTEST_F(AccountFileOperatorTest, AccountFileOperator001, TestSize.Level3)
{
    auto accountFileOperator_ = std::make_shared<AccountFileOperator>();
    EXPECT_EQ(accountFileOperator_->DeleteDirOrFile("../../xx"), ERR_OK);
    EXPECT_EQ(accountFileOperator_->IsExistFile(""), false);
    EXPECT_EQ(accountFileOperator_->IsJsonFormat("../&*&"), false);
    EXPECT_EQ(accountFileOperator_->IsExistDir(""), false);
}

/**
 * @tc.name: AccountFileTransaction001
 * @tc.desc: Test GetFileTransaction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountFileOperatorTest, AccountFileTransaction001, TestSize.Level1)
{
    auto accountFileOperator_ = std::make_shared<AccountFileOperator>();
    accountFileOperator_->DeleteDirOrFile(TEST_FILE_PATH);
    TransactionShared transaction = nullptr;
    transaction = accountFileOperator_->GetFileTransaction(TEST_FILE_PATH);
    ASSERT_NE(nullptr, transaction);
    auto lockShared = accountFileOperator_->GetRWLock(TEST_FILE_PATH);
    ASSERT_NE(nullptr, lockShared);
    // transaction, map, lockShared, have 3 copy
    int32_t expectCnt = 3;
    EXPECT_EQ(lockShared.use_count(), expectCnt);
    transaction = nullptr;
    expectCnt = 2;
    EXPECT_EQ(lockShared.use_count(), expectCnt);
    transaction = std::make_shared<FileTransaction>(TEST_FILE_PATH, lockShared);
    // lockShared is only handeled by map and transaction
    lockShared = nullptr;
    // when transaction is released, the lock in map should be released
    transaction = nullptr;
    lockShared = accountFileOperator_->GetRWLock(TEST_FILE_PATH);
    // release lock
    transaction = std::make_shared<FileTransaction>(TEST_FILE_PATH, lockShared);
}

/**
 * @tc.name: AccountFileTransaction002
 * @tc.desc: File transaction write success, not existing target file
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountFileOperatorTest, AccountFileTransaction002, TestSize.Level1)
{
    auto accountFileOperator_ = std::make_shared<AccountFileOperator>();
    accountFileOperator_->DeleteDirOrFile(TEST_FILE_PATH);
    TransactionShared transaction = nullptr;
    transaction = accountFileOperator_->GetFileTransaction(TEST_FILE_PATH);
    ASSERT_NE(nullptr, transaction);
    EXPECT_FALSE(transaction->IsTempFileExist());
    EXPECT_FALSE(accountFileOperator_->IsExistFile(TEST_FILE_PATH));

    ASSERT_EQ(ERR_OK, transaction->BeginWriteTransaction());
    EXPECT_TRUE(transaction->IsTempFileExist());
    EXPECT_FALSE(accountFileOperator_->IsExistFile(TEST_FILE_PATH));

    std::string testString = "test string";
    ErrCode ret = transaction->WriteFile(testString);
    ASSERT_EQ(ERR_OK, ret);

    ret = transaction->EndTransaction();
    ASSERT_EQ(ERR_OK, ret);
    EXPECT_FALSE(transaction->IsTempFileExist());
    EXPECT_TRUE(accountFileOperator_->IsExistFile(TEST_FILE_PATH));

    std::string readString = "";
    transaction->ReadFile(readString);
    ASSERT_EQ(readString, testString);
}

/**
 * @tc.name: AccountFileTransaction003
 * @tc.desc: File transaction write success, existing target file
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountFileOperatorTest, AccountFileTransaction003, TestSize.Level1)
{
    auto accountFileOperator_ = std::make_shared<AccountFileOperator>();
    accountFileOperator_->DeleteDirOrFile(TEST_FILE_PATH);
    std::string originalContext = "test";
    std::string cmd = "echo \"" + originalContext + "\" > " + TEST_FILE_PATH;
    system(cmd.c_str());
    originalContext += "\n"; // echo would add "\n"

    TransactionShared transaction = nullptr;
    transaction = accountFileOperator_->GetFileTransaction(TEST_FILE_PATH);
    ASSERT_NE(nullptr, transaction);
    EXPECT_FALSE(transaction->IsTempFileExist());
    EXPECT_TRUE(accountFileOperator_->IsExistFile(TEST_FILE_PATH));

    ASSERT_EQ(ERR_OK, transaction->BeginWriteTransaction());
    EXPECT_TRUE(transaction->IsTempFileExist());
    EXPECT_TRUE(accountFileOperator_->IsExistFile(TEST_FILE_PATH));

    std::string testString = "test string";
    ErrCode ret = transaction->WriteFile(testString);
    ASSERT_EQ(ERR_OK, ret);

    std::fstream fin(transaction->GetPath());
    ASSERT_TRUE(fin.is_open());
    const size_t testBufSize = 100;
    char testBuf[testBufSize] = {0};
    fin.read(testBuf, testBufSize);
    ASSERT_EQ(std::string(testBuf), originalContext);

    std::fstream tmpFin(transaction->GetTempFilePath());
    ASSERT_TRUE(tmpFin.is_open());
    char testTmpBuf[testBufSize] = {0};
    tmpFin.read(testTmpBuf, testBufSize);
    ASSERT_EQ(std::string(testTmpBuf), testString);

    ret = transaction->EndTransaction();
    ASSERT_EQ(ERR_OK, ret);
    EXPECT_FALSE(transaction->IsTempFileExist());
    EXPECT_TRUE(accountFileOperator_->IsExistFile(TEST_FILE_PATH));

    fin.close();
    tmpFin.close();
    fin.open(transaction->GetPath());
    fin.read(testBuf, testBufSize);
    ASSERT_EQ(std::string(testBuf), testString);
}

/**
 * @tc.name: AccountFileTransaction004
 * @tc.desc: File transaction auto rollback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountFileOperatorTest, AccountFileTransaction004, TestSize.Level1)
{
    auto accountFileOperator_ = std::make_shared<AccountFileOperator>();
    accountFileOperator_->DeleteDirOrFile(TEST_FILE_PATH);
    TransactionShared transaction = nullptr;
    transaction = accountFileOperator_->GetFileTransaction(TEST_FILE_PATH);
    ASSERT_NE(nullptr, transaction);
    EXPECT_FALSE(transaction->IsTempFileExist());
    EXPECT_FALSE(accountFileOperator_->IsExistFile(TEST_FILE_PATH));

    ASSERT_EQ(ERR_OK, transaction->BeginWriteTransaction());
    EXPECT_TRUE(transaction->IsTempFileExist());
    EXPECT_FALSE(accountFileOperator_->IsExistFile(TEST_FILE_PATH));

    transaction = nullptr;
    EXPECT_FALSE(FileTransaction::IsTempFileExist(TEST_FILE_PATH));
    EXPECT_FALSE(accountFileOperator_->IsExistFile(TEST_FILE_PATH));
}

/**
 * @tc.name: AccountFileTransaction005
 * @tc.desc: File transaction commit when not write
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountFileOperatorTest, AccountFileTransaction005, TestSize.Level1)
{
    auto accountFileOperator_ = std::make_shared<AccountFileOperator>();
    accountFileOperator_->DeleteDirOrFile(TEST_FILE_PATH);
    TransactionShared transaction = nullptr;
    transaction = accountFileOperator_->GetFileTransaction(TEST_FILE_PATH);
    ASSERT_NE(nullptr, transaction);
    EXPECT_FALSE(transaction->IsTempFileExist());
    EXPECT_FALSE(accountFileOperator_->IsExistFile(TEST_FILE_PATH));

    ASSERT_EQ(ERR_OK, transaction->BeginWriteTransaction());
    EXPECT_TRUE(transaction->IsTempFileExist());
    EXPECT_FALSE(accountFileOperator_->IsExistFile(TEST_FILE_PATH));

    ErrCode ret = transaction->EndTransaction();
    ASSERT_EQ(ERR_OK, ret);
    EXPECT_FALSE(transaction->IsTempFileExist());
    EXPECT_FALSE(accountFileOperator_->IsExistFile(TEST_FILE_PATH));
}

/**
 * @tc.name: AccountFileTransaction006
 * @tc.desc: File transaction force unlock, then write again
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountFileOperatorTest, AccountFileTransaction006, TestSize.Level1)
{
    auto accountFileOperator_ = std::make_shared<AccountFileOperator>();
    accountFileOperator_->DeleteDirOrFile(TEST_FILE_PATH);
    TransactionShared transaction = nullptr;
    transaction = accountFileOperator_->GetFileTransaction(TEST_FILE_PATH);
    ASSERT_NE(nullptr, transaction);
    EXPECT_FALSE(transaction->IsTempFileExist());
    EXPECT_FALSE(accountFileOperator_->IsExistFile(TEST_FILE_PATH));

    ASSERT_EQ(ERR_OK, transaction->BeginWriteTransaction());
    EXPECT_TRUE(transaction->IsTempFileExist());
    EXPECT_FALSE(accountFileOperator_->IsExistFile(TEST_FILE_PATH));

    std::string testString = "test string, first write";
    ErrCode ret = transaction->WriteFile(testString);
    ASSERT_EQ(ERR_OK, ret);

    transaction->ForceUnlock();
    EXPECT_TRUE(FileTransaction::IsTempFileExist(TEST_FILE_PATH));
    EXPECT_FALSE(accountFileOperator_->IsExistFile(TEST_FILE_PATH));
    transaction = nullptr;
    EXPECT_TRUE(FileTransaction::IsTempFileExist(TEST_FILE_PATH));
    EXPECT_FALSE(accountFileOperator_->IsExistFile(TEST_FILE_PATH));

    transaction = accountFileOperator_->GetFileTransaction(TEST_FILE_PATH);
    ASSERT_EQ(ERR_OK, transaction->BeginWriteTransaction());
    std::string secondTestString = "test string, second write";
    ret = transaction->WriteFile(secondTestString);
    ASSERT_EQ(ERR_OK, ret);
    ret = transaction->EndTransaction();
    ASSERT_EQ(ERR_OK, ret);
    
    std::string content;
    ASSERT_EQ(ERR_OK, transaction->ReadFile(content));
    ASSERT_EQ(secondTestString, content);
}

/**
 * @tc.name: AccountFileTransaction007
 * @tc.desc: File transaction write twice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountFileOperatorTest, AccountFileTransaction007, TestSize.Level2)
{
    auto accountFileOperator_ = std::make_shared<AccountFileOperator>();
    accountFileOperator_->DeleteDirOrFile(TEST_FILE_PATH);
    TransactionShared transaction = nullptr;
    transaction = accountFileOperator_->GetFileTransaction(TEST_FILE_PATH);
    ASSERT_NE(nullptr, transaction);
    EXPECT_FALSE(transaction->IsTempFileExist());
    EXPECT_FALSE(accountFileOperator_->IsExistFile(TEST_FILE_PATH));

    ASSERT_EQ(ERR_OK, transaction->BeginWriteTransaction());
    EXPECT_TRUE(transaction->IsTempFileExist());
    EXPECT_FALSE(accountFileOperator_->IsExistFile(TEST_FILE_PATH));

    std::string testString = "test string1";
    ErrCode ret = transaction->WriteFile(testString);
    ASSERT_EQ(ERR_OK, ret);

    std::string testString2 = "test string2";
    ret = transaction->WriteFile(testString2);
    ASSERT_EQ(ERR_OK, ret);

    ret = transaction->EndTransaction();
    ASSERT_EQ(ERR_OK, ret);
    EXPECT_FALSE(transaction->IsTempFileExist());
    EXPECT_TRUE(accountFileOperator_->IsExistFile(TEST_FILE_PATH));

    std::string readString = "";
    transaction->ReadFile(readString);
    ASSERT_EQ(readString, testString2);
}

/**
 * @tc.name: AccountFileTransaction008
 * @tc.desc: File transaction write two thread
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountFileOperatorTest, AccountFileTransaction008, TestSize.Level2)
{
    auto accountFileOperator_ = std::make_shared<AccountFileOperator>();
    accountFileOperator_->DeleteDirOrFile(TEST_FILE_PATH);
    TransactionShared transaction1 = nullptr;
    transaction1 = accountFileOperator_->GetFileTransaction(TEST_FILE_PATH);
    ASSERT_NE(nullptr, transaction1);
    TransactionShared transaction2 = nullptr;
    transaction2 = accountFileOperator_->GetFileTransaction(TEST_FILE_PATH);
    ASSERT_NE(nullptr, transaction2);

    ASSERT_EQ(ERR_OK, transaction1->BeginWriteTransaction());
    std::mutex mtx;
    std::condition_variable cv;
    std::string test2Context = "test2Context";

    auto threadWork = [&]() {
        ASSERT_EQ(ERR_OK, transaction2->BeginWriteTransaction());
        ASSERT_EQ(ERR_OK, transaction2->WriteFile(test2Context));
        ASSERT_EQ(ERR_OK, transaction2->EndTransaction());
        cv.notify_one();
    };
    std::thread thread(threadWork);
    std::string threadName = "testThread";
    pthread_setname_np(thread.native_handle(), threadName.c_str());
    thread.detach();

    std::string test1Context = "test1Context";
    ASSERT_EQ(ERR_OK, transaction1->WriteFile(test1Context));
    ASSERT_EQ(ERR_OK, transaction1->EndTransaction());

    std::unique_lock<std::mutex> lock(mtx);
    cv.wait(lock);

    std::string readString = "";
    transaction1->ReadFile(readString);
    ASSERT_EQ(readString, test2Context);
}

