/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef ACCOUNT_IAM_CLIENT_TEST_CALLBACK_H
#define ACCOUNT_IAM_CLIENT_TEST_CALLBACK_H

#include <vector>
#include <memory>
#include <gmock/gmock.h>
#include "account_iam_client_callback.h"
#include "account_iam_info.h"

namespace OHOS {
namespace AccountTest {
class MockIDMCallback final {
public:
    MOCK_METHOD2(OnResult, void(int32_t result, const AccountSA::Attributes &extraInfo));
    MOCK_METHOD3(OnAcquireInfo, void(int32_t module, uint32_t acquireInfo, const AccountSA::Attributes &extraInfo));
};

class TestIDMCallback final : public AccountSA::IDMCallback {
public:
    TestIDMCallback(const std::shared_ptr<MockIDMCallback> &callback) :callback_(callback) {}
    virtual ~TestIDMCallback() {}
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const AccountSA::Attributes &extraInfo)
    {
        callback_->OnAcquireInfo(module, acquireInfo, extraInfo);
        std::unique_lock<std::mutex> lock(mutex);
        isReady = true;
        cv.notify_one();
        return;
    }
    void OnResult(int32_t result, const AccountSA::Attributes &extraInfo)
    {
        callback_->OnResult(result, extraInfo);
        std::unique_lock<std::mutex> lock(mutex);
        isReady = true;
        cv.notify_one();
        return;
    }
    std::condition_variable cv;
    bool isReady = false;
    std::mutex mutex;
private:
    std::shared_ptr<MockIDMCallback> callback_;
};

class MockGetCredInfoCallback final {
public:
    MOCK_METHOD2(OnCredentialInfo, void(int32_t result, const std::vector<AccountSA::CredentialInfo> &infoList));
};

class TestGetCredInfoCallback final : public AccountSA::GetCredInfoCallback {
public:
    TestGetCredInfoCallback(const std::shared_ptr<MockGetCredInfoCallback> &callback) :callback_(callback) {}
    virtual ~TestGetCredInfoCallback() {}
    void OnCredentialInfo(int32_t result, const std::vector<AccountSA::CredentialInfo> &infoList)
    {
        callback_->OnCredentialInfo(result, infoList);
        std::unique_lock<std::mutex> lock(mutex);
        isReady = true;
        cv.notify_one();
        return;
    }
    std::condition_variable cv;
    bool isReady = false;
    std::mutex mutex;
private:
    std::shared_ptr<MockGetCredInfoCallback> callback_;
};

class MockGetEnrolledIdCallback final {
public:
    MOCK_METHOD2(OnEnrolledId, void(int32_t result, uint64_t enrolledId));
};

class TestGetEnrolledIdCallback final : public AccountSA::GetEnrolledIdCallback {
public:
    TestGetEnrolledIdCallback(const std::shared_ptr<MockGetEnrolledIdCallback> &callback) :callback_(callback) {}
    virtual ~TestGetEnrolledIdCallback() {}
    void OnEnrolledId(int32_t result, uint64_t enrolledId)
    {
        callback_->OnEnrolledId(result, enrolledId);
        std::unique_lock<std::mutex> lock(mutex);
        isReady = true;
        cv.notify_one();
        return;
    }
    std::condition_variable cv;
    bool isReady = false;
    std::mutex mutex;
private:
    std::shared_ptr<MockGetEnrolledIdCallback> callback_;
};

class MockGetSetPropCallback final {
public:
    MOCK_METHOD2(OnResult, void(int32_t result, const AccountSA::Attributes &extraInfo));
};

class TestGetSetPropCallback final : public AccountSA::GetSetPropCallback {
public:
    TestGetSetPropCallback(const std::shared_ptr<MockGetSetPropCallback> &callback) :callback_(callback) {}
    virtual ~TestGetSetPropCallback() {}
    void OnResult(int32_t result, const AccountSA::Attributes &extraInfo)
    {
        callback_->OnResult(result, extraInfo);
        std::unique_lock<std::mutex> lock(mutex);
        isReady = true;
        cv.notify_one();
        return;
    }
    std::condition_variable cv;
    bool isReady = false;
    std::mutex mutex;
private:
    std::shared_ptr<MockGetSetPropCallback> callback_;
};
}  // namespace AccountTest
}  // namespace OHOS

#endif  // ACCOUNT_IAM_CLIENT_TEST_CALLBACK_H