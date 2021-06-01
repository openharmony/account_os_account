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

#include <fstream>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <iostream>

#include "account_error_no.h"
#include "account_info.h"
#include "account_log_wrapper.h"
#include "ohos_account_data_deal.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string RESOURCE_ROOT_PATH = "/data/test/account/data_deal/";
const std::string ACCOUNT_SUFFIX = ".json";
const std::string TEST_STR_ACCOUNT_NAME = "incubation";
const std::string TEST_STR_OPEN_ID = "test open id";
}

class OhosAccountDataDealTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();

protected:
    std::ostringstream pathStream_;
};

void OhosAccountDataDealTest::SetUpTestCase() {}

void OhosAccountDataDealTest::TearDownTestCase() {}

void OhosAccountDataDealTest::SetUp() {}

void OhosAccountDataDealTest::TearDown()
{
    pathStream_.clear();
}

/**
 * @tc.name: OhosAccountJsonNotInitTest001
 * @tc.desc: Test invalid event publish
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OhosAccountDataDealTest, OhosAccountJsonNotInitTest001, TestSize.Level0)
{
    AccountInfo accountInfo;
    pathStream_ << RESOURCE_ROOT_PATH << "test" << ACCOUNT_SUFFIX;

    /**
     * @tc.steps: step1. init json object
     */
    OhosAccountDataDeal dataDeal(pathStream_.str());
    ErrCode errCode = dataDeal.AccountInfoFromJson(accountInfo);
    EXPECT_EQ(errCode, ERR_ACCOUNT_DATADEAL_NOT_READY);
}

/**
 * @tc.name: OhosAccountJsonCreateDefaultJsonFileTest002
 * @tc.desc: Test invalid event publish
 * @tc.type: FUNC
 * @tc.require: AR000CUF6P
 */
HWTEST_F(OhosAccountDataDealTest, OhosAccountJsonCreateDefaultJsonFileTest002, TestSize.Level0)
{
    AccountInfo accountInfo;
    ErrCode errCode = ERR_OK;
    pathStream_ << RESOURCE_ROOT_PATH << "not_exist" << ACCOUNT_SUFFIX;

    /**
     * @tc.steps: step1. init json object
     */
    OhosAccountDataDeal dataDeal(pathStream_.str());
    errCode = dataDeal.Init();
    EXPECT_EQ(errCode, ERR_OK);

    errCode = dataDeal.AccountInfoFromJson(accountInfo);
    EXPECT_EQ(errCode, ERR_OK);
    EXPECT_EQ(accountInfo.ohosAccountStatus_, ACCOUNT_STATE_UNBOUND);
    EXPECT_EQ(accountInfo.ohosAccountName_, DEFAULT_OHOS_ACCOUNT_NAME);
}

/**
 * @tc.name: OhosAccountInvalidFileNameTest003
 * @tc.desc: Test invalid event publish
 * @tc.type: FUNC
 * @tc.require: AR000CUF6Q
 */
HWTEST_F(OhosAccountDataDealTest, OhosAccountInvalidFileNameTest003, TestSize.Level0)
{
    AccountInfo accountInfo;
    accountInfo.ohosAccountStatus_ = ACCOUNT_STATE_UNBOUND;
    ErrCode errCode = ERR_OK;
    pathStream_ << RESOURCE_ROOT_PATH << "invalid_format" << ACCOUNT_SUFFIX;

    /**
     * @tc.steps: step1. init json object
     */
    OhosAccountDataDeal dataDeal(pathStream_.str());
    errCode = dataDeal.Init();
    EXPECT_NE(errCode, ERR_OK);
}

/**
 * @tc.name: OhosAccountJsonFileWriteTest004
 * @tc.desc: Test invalid event publish
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OhosAccountDataDealTest, OhosAccountJsonFileWriteTest004, TestSize.Level0)
{
    AccountInfo accountInfo;
    ErrCode errCode = ERR_OK;
    pathStream_ << RESOURCE_ROOT_PATH << "valid" << ACCOUNT_SUFFIX;

    /**
     * @tc.steps: step1. init json object
     */
    OhosAccountDataDeal dataDeal(pathStream_.str());

    errCode = dataDeal.Init();
    EXPECT_EQ(errCode, ERR_OK);
    errCode = dataDeal.AccountInfoFromJson(accountInfo);
    EXPECT_EQ(errCode, ERR_OK);
    EXPECT_EQ(accountInfo.ohosAccountStatus_, ACCOUNT_STATE_UNBOUND);
    EXPECT_EQ(accountInfo.ohosAccountName_, TEST_STR_ACCOUNT_NAME);
    EXPECT_EQ(accountInfo.ohosAccountUid_, TEST_STR_OPEN_ID);

    /**
     * @tc.steps: step2. update json object
     */
    accountInfo.ohosAccountStatus_ = ACCOUNT_STATE_NOTLOGIN;
    accountInfo.ohosAccountName_ = TEST_STR_ACCOUNT_NAME;
    accountInfo.ohosAccountUid_ = TEST_STR_OPEN_ID;
    dataDeal.AccountInfoToJson(accountInfo);

    /**
     * @tc.steps: step3. read json object and validate info
     */
    OhosAccountDataDeal dataDealNew(pathStream_.str());
    errCode = dataDealNew.Init();
    EXPECT_EQ(errCode, ERR_OK);
    AccountInfo accountInfoNew;
    errCode = dataDeal.AccountInfoFromJson(accountInfoNew);
    EXPECT_EQ(errCode, ERR_OK);
    EXPECT_EQ(accountInfoNew.ohosAccountStatus_, ACCOUNT_STATE_NOTLOGIN);
    EXPECT_EQ(accountInfoNew.ohosAccountName_, TEST_STR_ACCOUNT_NAME);
    EXPECT_EQ(accountInfoNew.ohosAccountUid_, TEST_STR_OPEN_ID);
}