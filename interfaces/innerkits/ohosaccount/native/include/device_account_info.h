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

#ifndef BASE_ACCOUNT_DEVICE_ACCOUNT_INFO_H
#define BASE_ACCOUNT_DEVICE_ACCOUNT_INFO_H

#include "string_ex.h"
#include "message_parcel.h"

namespace OHOS {
namespace AccountSA {
/**
 * Device account type.
 */
enum class DeviceAccountType {
    DEVICE_ACCOUNT_TYPE_INVALID = -1, // invalid type
    DEVICE_ACCOUNT_TYPE_OWNER = 0, // device owner account
    DEVICE_ACCOUNT_TYPE_NORMAL, // device normal account
    DEVICE_ACCOUNT_TYPE_HIDDEN_SPACE, // device hidden space account
    DEVICE_ACCOUNT_TYPE_REPAIR_MODE, // device repair account
    DEVICE_ACCOUNT_TYPE_GUEST, // device guest account
};

/**
 * Device account state.
 */
enum class DeviceAccountState {
    DEVICE_ACCOUNT_STATE_INVALID = -1, // invalid state
    DEVICE_ACCOUNT_STATE_BOOTING = 0, // device account is booting
    DEVICE_ACCOUNT_STATE_RUNNING_LOCKED, // device account is locked
    DEVICE_ACCOUNT_STATE_RUNNING_UNLOCKING, // device account is unlocking
    DEVICE_ACCOUNT_STATE_RUNNING_UNLOCKED, // device account is unlocked
    DEVICE_ACCOUNT_STATE_STOPPING, // device account is stopping
    DEVICE_ACCOUNT_STATE_SHUTDOWN, // device account is shutdown
};

/**
 * Invalid device account id.
 */
constexpr std::int32_t DEVICE_ACCOUNT_ID_INVALID = -1;

/**
 * Device account owner
 */
constexpr std::int32_t DEVICE_ACCOUNT_OWNER = 0;

/**
 * no error
 */
constexpr std::int32_t ERROR_NONE = 0;

/**
 * error
 */
constexpr std::int32_t ERROR_HAPPEN = -1;

class DeviceAccountInfo {
public:
    /**
     * Device account ID.
     */
    std::int32_t id_;

    /**
     * Device account type.
     */
    DeviceAccountType type_;

    /**
     * Device account name.
     */
    std::string name_;

    /**
     * Device account icon path.
     */
    std::string iconPath_;

    /**
     * Device account state.
     */
    DeviceAccountState state_;

    /**
     * Device account flags, like admin or system flag.
     */
    std::int32_t flags_;

    /**
     * Device account create time.
     */
    int64_t creationTime_;

    /**
     * Device account last logged time.
     */
    int64_t lastLoginTime_;

    /**
     * Guest device account to be removed.
     */
    bool guestToRemoved_;

    /**
     * Device account information class default Constructor.
     */
    DeviceAccountInfo()
    {
        id_ = DEVICE_ACCOUNT_ID_INVALID;
        type_ = DeviceAccountType::DEVICE_ACCOUNT_TYPE_INVALID;
        name_.clear();
        iconPath_.clear();
        state_ = DeviceAccountState::DEVICE_ACCOUNT_STATE_INVALID;
        flags_ = 0;
        creationTime_ = 0;
        lastLoginTime_ = 0;
        guestToRemoved_ = false;
    }

    /**
     * Device account information class Constructor.
     */
    DeviceAccountInfo(const std::int32_t accountId, const DeviceAccountType accountType, const std::string &accountName)
        : id_(accountId), type_(accountType), name_(accountName)
    {
        iconPath_.clear();
        state_ = DeviceAccountState::DEVICE_ACCOUNT_STATE_INVALID;
        flags_ = 0;
        creationTime_ = 0;
        lastLoginTime_ = 0;
        guestToRemoved_ = false;
    }

    /**
     * Device account information class Constructor.
     */
    DeviceAccountInfo(const std::int32_t accountId, const DeviceAccountType accountType,
        const std::string &accountName, const std::string &path)
        : id_(accountId), type_(accountType), name_(accountName), iconPath_(path)
    {
        state_ = DeviceAccountState::DEVICE_ACCOUNT_STATE_INVALID;
        flags_ = 0;
        creationTime_ = 0;
        lastLoginTime_ = 0;
        guestToRemoved_ = false;
    }

    /**
     * Device account information class default Destructor.
     */
    ~DeviceAccountInfo() {}

    /**
     * == redefinition
     *
     * @return whether id is equal
     */
    bool operator==(const DeviceAccountInfo &source)
    {
        return ((id_ == source.id_) && (id_ != DEVICE_ACCOUNT_ID_INVALID));
    }

    /**
     * write device account info to parcel
     *
     * @return 0 when succeeded, otherwise -1
     */
    std::int32_t WriteDataToParcel(MessageParcel &data)
    {
        if (!data.WriteInt32(id_)) {
            return ERROR_HAPPEN;
        }

        if (!data.WriteInt32(static_cast<std::int32_t>(type_))) {
            return ERROR_HAPPEN;
        }

        if (!data.WriteString16(Str8ToStr16(name_))) {
            return ERROR_HAPPEN;
        }

        if (!data.WriteInt32(static_cast<std::int32_t>(state_))) {
            return ERROR_HAPPEN;
        }

        return ERROR_NONE;
    }

    /**
     * read device account info from parcel
     *
     */
    void ReadDataFromParcel(MessageParcel &data)
    {
        id_ = data.ReadInt32();
        type_ = static_cast<DeviceAccountType>(data.ReadInt32());
        name_ = Str16ToStr8(data.ReadString16());
        state_ = static_cast<DeviceAccountState>(data.ReadInt32());
    }
};
} // namespace AccountSA
} // namespace OHOS
#endif // BASE_ACCOUNT_DEVICE_ACCOUNT_INFO_H
