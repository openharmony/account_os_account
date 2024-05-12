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

/**
 * @addtogroup OsAccount
 * @{
 *
 * @brief Provides os account management.
 *
 * Provides abilities for you to manage and perform operations on your OS accounts.
 *
 * @since 7.0
 * @version 7.0
 */

/**
 * @file os_account_manager.h
 *
 * @brief Declares os account manager interfaces.
 *
 * @since 7.0
 * @version 7.0
 */

#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_OS_ACCOUNT_MANAGER_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_OS_ACCOUNT_MANAGER_H

#include <string>
#include <vector>
#include "domain_account_callback.h"
#include "os_account_info.h"
#include "os_account_subscriber.h"
#include "account_error_no.h"
namespace OHOS {
namespace AccountSA {
class OsAccountManager {
public:
    /**
     * @brief Creates an OS account using the local name and account type.
     * @permission ohos.permission.MANAGE_LOCAL_ACCOUNTS
     * @param localName - Indicates the local name of the OS account to create.
     * @param type - Indicates the type of the OS account to create.
     * @param osAccountInfo - Indicates the information about the created OS account.
     * @return error code, see account_error_no.h
     */
    static ErrCode CreateOsAccount(const std::string &name, const OsAccountType &type, OsAccountInfo &osAccountInfo);

    /**
     * @brief Creates an OS account using the local name, short name and account type.
     * @permission ohos.permission.MANAGE_LOCAL_ACCOUNTS
     * @param localName - Indicates the local name of the OS account to create.
     * @param shortName - Indicates the short name of the OS account to create.
     * @param type - Indicates the type of the OS account to create.
     * @param osAccountInfo - Indicates the information about the created OS account.
     * @return error code, see account_error_no.h
     */
    static ErrCode CreateOsAccount(const std::string& localName, const std::string& shortName,
        const OsAccountType& type, OsAccountInfo& osAccountInfo);

    /**
     * @brief Creates an OS account using the local name, short name, account type and other options.
     * @permission ohos.permission.MANAGE_LOCAL_ACCOUNTS
     * @param localName - Indicates the local name of the OS account to create.
     * @param shortName - Indicates the short name of the OS account to create.
     * @param type - Indicates the type of the OS account to create.
     * @param options - Indicates the options of the OS account to create.
     *                - Include disallowedHapList - Indicates the disallowed install hap list.
     * @param osAccountInfo - Indicates the information about the created OS account.
     * @return error code, see account_error_no.h
     */
    static ErrCode CreateOsAccount(const std::string& localName, const std::string& shortName,
        const OsAccountType& type, const CreateOsAccountOptions& options, OsAccountInfo& osAccountInfo);

    /**
     * @brief Creates an OS account using full user info
     * @permission ohos.permission.MANAGE_LOCAL_ACCOUNTS
     * @param osAccountInfo - Indicates the information about the created OS account.
     * @return error code, see account_error_no.h
     */
    static ErrCode CreateOsAccountWithFullInfo(OsAccountInfo &osAccountInfo);

    /**
     * @brief Updates an OS account using full user info
     * @permission ohos.permission.MANAGE_LOCAL_ACCOUNTS
     * @param osAccountInfo - Indicates the information about the created OS account.
     * @return error code, see account_error_no.h
     */
    static ErrCode UpdateOsAccountWithFullInfo(OsAccountInfo &osAccountInfo);

    /**
     * @brief Creates an OS account using the account type and domain account info.
     * @permission ohos.permission.MANAGE_LOCAL_ACCOUNTS
     * @param type - Indicates the type of the OS account to create.
     * @param domainInfo - Indicates the domain account info.
     * @param callback - Indicates the callback for getting the information of the created OS account.
     * @return error code, see account_error_no.h
     */
    static ErrCode CreateOsAccountForDomain(const OsAccountType &type, const DomainAccountInfo &domainInfo,
        const std::shared_ptr<DomainAccountCallback> &callback, const CreateOsAccountForDomainOptions& options = {});

    /**
     * @brief Removes an OS account based on its local ID.
     * @permission ohos.permission.MANAGE_LOCAL_ACCOUNTS
     * @param id - Indicates the local ID of the OS account.
     * @return error code, see account_error_no.h
     */
    static ErrCode RemoveOsAccount(const int id);

    /**
     * @brief Checks whether the specified OS account exists.
     * @param id - Indicates the local ID of the OS account.
     * @param isOsAccountExists - Indicates whether the specified OS account exists.
     * @return error code, see account_error_no.h
     */
    static ErrCode IsOsAccountExists(const int id, bool &isOsAccountExists);

    /**
     * @brief Checks whether an OS account is activated based on its local ID.
     * @permission ohos.permission.MANAGE_LOCAL_ACCOUNTS or ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS
     * @param id - Indicates the local ID of the OS account.
     * @param isOsAccountActived - Indicates whether the OS account is activated.
     * @return error code, see account_error_no.h
     */
    static ErrCode IsOsAccountActived(const int id, bool &isOsAccountActived);

    /**
     * @brief Checks whether the specified constraint is enabled for the specified OS account.
     * @param id - Indicates the local ID of the OS account.
     * @param constriaint - Indicates the constraint.
     * @param isConstraintEnable - Indicates whether the specified constraint is enabled.
     * @return error code, see account_error_no.h
     */
    static ErrCode IsOsAccountConstraintEnable(const int id, const std::string &constraint, bool &isConstraintEnable);

    /**
     * @brief Checks whether the specified constraint is enabled for the specified OS account.
     * @param id - Indicates the local ID of the OS account.
     * @param constriaint - Indicates the constraint.
     * @param isEnabled - Indicates whether the specified constraint is enabled.
     * @return error code, see account_error_no.h
     */
    static ErrCode CheckOsAccountConstraintEnabled(
        const int id, const std::string &constraint, bool &isEnabled);

    /**
     * @brief Checks whether the specified OS account is verified.
     * @param id - Indicates the local ID of the OS account.
     * @param isVerified - Indicates whether the current OS account is verified.
     * @return error code, see account_error_no.h
     */
    static ErrCode IsOsAccountVerified(const int id, bool &isVerified);

    /**
     * @brief Gets the number of all OS accounts created on a device.
     * @permission ohos.permission.MANAGE_LOCAL_ACCOUNTS
     * @param osAccountsCount - Returns the number of created OS accounts.
     * @return error code, see account_error_no.h
     */
    static ErrCode GetCreatedOsAccountsCount(unsigned int &osAccountsCount);

    /**
     * @brief Gets the local ID of the current OS account.
     * @param id - Indicates the local ID of the current OS account.
     * @return error code, see account_error_no.h
     */
    static ErrCode GetOsAccountLocalIdFromProcess(int &id);

    /**
     * @brief Checks whether current process belongs to the main account.
     * @permission ohos.permission.MANAGE_LOCAL_ACCOUNTS
     * @param isMainOsAccount - Indicates whether the current process belongs to the main OS account.
     * @return error code, see account_error_no.h
     */
    static ErrCode IsMainOsAccount(bool &isMainOsAccount);

    /**
     * @brief Gets the local ID of an OS account from the process UID
     * @param uid - Indicates the process UID.
     * @param id - Indicates the local ID of the OS account associated with the specified UID.
     * @return error code, see account_error_no.h
     */
    static ErrCode GetOsAccountLocalIdFromUid(const int uid, int &id);

    /**
     * @brief Gets the bundle ID associated with the specified UID.
     * @param uid - Indicates the target uid.
     * @param bundleId - Indicates the bundle ID associated with the specified UID.
     * @return error code, see account_error_no.h
     */
    static ErrCode GetBundleIdFromUid(const int uid, int &bundleId);

    /**
     * @brief Gets the local ID of the OS account associated with the specified domain account.
     * @permission ohos.permission.MANAGE_LOCAL_ACCOUNTS
     * @param domainInfo - Indicates the domain account info.
     * @param id - Indicates the local ID of the OS account associated with the specified domain account.
     * @return error code, see account_error_no.h
     */
    static ErrCode GetOsAccountLocalIdFromDomain(const DomainAccountInfo &domainInfo, int &id);

    /**
     * @brief Queries the maximum number of OS accounts that can be created on a device.
     * @param maxOsAccountNumber - Returns the maximum number of OS accounts that can be created.
     * @return error code, see account_error_no.h
     */
    static ErrCode QueryMaxOsAccountNumber(uint32_t &maxOsAccountNumber);

    /**
     * @brief Queries the maximum number of OS accounts that can be logged in.
     * @param maxNum - Returns the maximum number of OS accounts that can be created.
     * @return error code, see account_error_no.h
     */
    static ErrCode QueryMaxLoggedInOsAccountNumber(uint32_t &maxNum);

    /**
     * @brief Gets all constraints of an account based on its ID.
     * @permission ohos.permission.MANAGE_LOCAL_ACCOUNTS
     * @param localId - Indicates the local ID of the OS account.
     * @param constraints - Indicates a list of constraints.
     * @return error code, see account_error_no.h
     */
    static ErrCode GetOsAccountAllConstraints(const int id, std::vector<std::string> &constraints);

    /**
     * @brief Queries the list of all the OS accounts that have been created in the system.
     * @permission ohos.permission.MANAGE_LOCAL_ACCOUNTS
     * @param osAccountInfos - Indicates a list of OS accounts.
     * @return error code, see account_error_no.h
     */
    static ErrCode QueryAllCreatedOsAccounts(std::vector<OsAccountInfo> &osAccountInfos);

    /**
     * @brief Gets information about the current OS account.
     * @permission ohos.permission.MANAGE_LOCAL_ACCOUNTS
     * @param osAccountInfo - Indicates the information about the current OS account.
     * @return error code, see account_error_no.h
     */
    static ErrCode QueryCurrentOsAccount(OsAccountInfo &osAccountInfo);

    /**
     * @brief Queries OS account information based on the local ID.
     * @permission ohos.permission.MANAGE_LOCAL_ACCOUNTS or ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION
     * @param localId - Indicates the local ID of the OS account.
     * @param osAccountInfo - Indicates the OS account information.
     * @return error code, see account_error_no.h
     */
    static ErrCode QueryOsAccountById(const int id, OsAccountInfo &osAccountInfo);

    /**
     * @brief Gets the type of this OS account from the current process.
     * @param type - Indicates the OS account type.
     * @return error code, see account_error_no.h
     */
    static ErrCode GetOsAccountTypeFromProcess(OsAccountType &type);

    /**
     * @brief Gets the type of this OS account from the current process.
     * @permission ohos.permission.MANAGE_LOCAL_ACCOUNTS or ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS
     * @param id - Indicates the local ID of the OS account.
     * @param type - Indicates the OS account type.
     * @return error code, see account_error_no.h
     */
    static ErrCode GetOsAccountType(const int id, OsAccountType& type);

    /**
     * @brief Gets the profile photo of an OS account based on its local ID.
     * @permission ohos.permission.MANAGE_LOCAL_ACCOUNTS
     * @param id - Indicates the local ID of the OS account.
     * @param photo - Indicates the profile photo.
     * @return error code, see account_error_no.h
     */
    static ErrCode GetOsAccountProfilePhoto(const int id, std::string &photo);

    /**
     * @brief Checks whether the function of supporting multiple OS accounts is enabled.
     * @param isMultiOsAccountEnable - Indicates whether multiple OS account feature is enabled.
     * @return error code, see account_error_no.h
     */
    static ErrCode IsMultiOsAccountEnable(bool &isMultiOsAccountEnable);

    /**
     * @brief Sets the local name for an OS account based on its local ID.
     * @permission ohos.permission.MANAGE_LOCAL_ACCOUNTS
     * @param localId - Indicates the local ID of the OS account.
     * @param localName - Indicates the local name to set for the OS account.
     * @return error code, see account_error_no.h
     */
    static ErrCode SetOsAccountName(const int id, const std::string &localName);

    /**
     * @brief Sets constraints for an OS account based on its local ID.
     * @permission ohos.permission.MANAGE_LOCAL_ACCOUNTS
     * @param localId - Indicates the local ID of the OS account.
     * @param constraints - Indicates the constraints to set for the OS account. The value can be:
     *        <ul>
     *        <li>{@code constraint.wifi.set} - Indicates the constraint on configuring the Wi-Fi access point.
     *        </li>
     *        <li>{@code constraint.sms.use} - Indicates the constraint on sending and receiving short messages.
     *        </li>
     *        <li>{@code constraint.calls.outgoing} - Indicates the constraint on making calls.</li>
     *        <li>{@code constraint.unknown.sources.install} - Indicates the constraint on installing applications
     *        from unknown sources.</li>
     *        </ul>
     * @param enable - Specifies whether to enable the constraint.
     * @return error code, see account_error_no.h
     */
    static ErrCode SetOsAccountConstraints(
        const int id, const std::vector<std::string> &constraints, const bool enable);

    /**
     * @brief Sets the profile photo for an OS account based on its local ID.
     * @permission ohos.permission.MANAGE_LOCAL_ACCOUNTS
     * @param localId - Indicates the local ID of the OS account.
     * @param photo - Indicates the profile photo to set for the OS account.
     * @return error code, see account_error_no.h
     */
    static ErrCode SetOsAccountProfilePhoto(const int id, const std::string &photo);

    /**
     * @brief Gets the distributed virtual device ID (DVID).
     * <p>
     * If the same OHOS account has logged in to multiple devices, these devices constitute a super device
     * through the distributed networking. On the connected devices, you can call this method to obtain the DVIDs.
     * The same application running on different devices obtains the same DVID, whereas different applications
     * obtain different DVIDs.
     * <p>
     *
     * @permission ohos.permission.DISTRIBUTED_DATASYNC or ohos.permission.MANAGE_LOCAL_ACCOUNTS
     * @param deviceId - Indicates the DVID if obtained; returns an empty string if no OHOS account has logged in.
     * @return error code, see account_error_no.h
     */
    static ErrCode GetDistributedVirtualDeviceId(std::string &deviceId);

    /**
     * @brief Activates a specified OS account.
     * <p>
     * If multiple OS accounts are available, you can call this method to enable a specific OS account
     * to run in the foreground. Then, the OS account originally running in the foreground will be
     * switched to the background.
     * </p>
     *
     * @permission ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION
     * @param id - Indicates the local ID of the OS account.
     * @return error code, see account_error_no.h
     */
    static ErrCode ActivateOsAccount(const int id);

    /**
     * @brief Deactivates a specified OS account.
     * <p>
     * You can call this method to disable a specific OS account.
     * </p>
     *
     * @permission ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION
     * @param id - Indicates the local ID of the OS account.
     * @return error code, see account_error_no.h
     */
    static ErrCode DeactivateOsAccount(const int id);

    /**
     * @brief Deactivates all OS account.
     * <p>
     * You can call this method to disable all OS account.
     * </p>
     *
     * @permission ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION
     * @return error code, see account_error_no.h
     */
    static ErrCode DeactivateAllOsAccounts();

    /**
     * @brief Starts the specified OS account.
     * @param id - Indicates the local ID of the OS account.
     * @return error code, see account_error_no.h
     */
    static ErrCode StartOsAccount(const int id);

    /**
     * @brief Gets localId according to serial number.
     * @param serialNumber - Indicates serial number.
     * @param id - Indicates the local ID of the OS account.
     * @return error code, see account_error_no.h
     */
    static ErrCode GetOsAccountLocalIdBySerialNumber(const int64_t serialNumber, int &id);

    /**
     * @brief Gets serial number according to localId.
     * @param localId - Indicates the local ID of the OS account.
     * @param serialNumber - Indicates the serial number.
     * @return error code, see account_error_no.h
     */
    static ErrCode GetSerialNumberByOsAccountLocalId(const int &id, int64_t &serialNumber);

    /**
     * @brief Subscribes the event of an OS account by the subscriber.
     * @param subscriber subscriber information
     * @return error code, see account_error_no.h
     */
    static ErrCode SubscribeOsAccount(const std::shared_ptr<OsAccountSubscriber> &subscriber);

    /**
     * @brief Unsubscribes the event of an OS account by the subscriber.
     * @param subscriber subscriber information
     * @return error code, see account_error_no.h
     */
    static ErrCode UnsubscribeOsAccount(const std::shared_ptr<OsAccountSubscriber> &subscriber);

    /**
     * @brief Gets the OS account switch mode.
     * @return switch mode
     */
    static OS_ACCOUNT_SWITCH_MOD GetOsAccountSwitchMod();

    /**
     * @brief Checks whether the current OS account is verified.
     * @param isVerified - Indicates whether the current OS account is verified.
     * @return error code, see account_error_no.h
     */
    static ErrCode IsCurrentOsAccountVerified(bool &isVerified);

    /**
     * @brief Checks whether the specified OS account is created completely.
     * @param id - Indicates the local ID of the specified OS account.
     * @param isOsAccountCompleted - Indicates whether the current OS account is created completely.
     * @return error code, see account_error_no.h
     */
    static ErrCode IsOsAccountCompleted(const int id, bool &isOsAccountCompleted);

    /**
     * @brief Sets the current OS account to be verified.
     * @param isVerified - Indicates whether the current OS account is verified.
     * @return error code, see account_error_no.h
     */
    static ErrCode SetCurrentOsAccountIsVerified(const bool isVerified);

    /**
     * @brief Sets the specified OS account to be verified.
     * @param id - Indicates the local ID of the specified OS account.
     * @param isVerified - Indicates whether the current OS account is verified.
     * @return error code, see account_error_no.h
     */
    static ErrCode SetOsAccountIsVerified(const int id, const bool isVerified);

    /**
     * @brief Gets the number of the created OS account from database.
     * @param storeID - Indicates the store ID.
     * @param id - Indicates the number of the created OS account.
     * @return error code, see account_error_no.h
     */
    static ErrCode GetCreatedOsAccountNumFromDatabase(const std::string& storeID, int &createdOsAccountNum);

    /**
     * @brief Get serial number from database.
     * @param storeID - Indicates the store ID.
     * @param serialNumber - Indicates the serial number.
     * @return error code, see account_error_no.h
     */
    static ErrCode GetSerialNumberFromDatabase(const std::string& storeID, int64_t &serialNumber);

    /**
     * @brief Gets the max ID of the OS account to be created.
     * @param storeID - Indicates the store ID.
     * @param id - Indicates the max ID of the OS account to be created.
     * @return error code, see account_error_no.h
     */
    static ErrCode GetMaxAllowCreateIdFromDatabase(const std::string& storeID, int &id);

    /**
     * @brief Sets the specified OS account from database.
     * @param storeID - Indicates the store ID.
     * @param id - Indicates the local ID of the specified OS account.
     * @param osAccountInfo - Indicates the OS account information.
     * @return error code, see account_error_no.h
     */
    static ErrCode GetOsAccountFromDatabase(const std::string& storeID, const int id, OsAccountInfo &osAccountInfo);

    /**
     * @brief Get a list of OS accounts from database.
     * @param storeID - Indicates the store ID.
     * @param osAccountList - Indicates a list of OS accounts.
     * @return error code, see account_error_no.h
     */
    static ErrCode GetOsAccountListFromDatabase(const std::string& storeID, std::vector<OsAccountInfo> &osAccountList);

    /**
     * @brief Gets the local IDs of all activated OS accounts.
     * @param ids - Indicates the local IDs of all activated OS accounts.
     * @return error code, see account_error_no.h
     */
    static ErrCode QueryActiveOsAccountIds(std::vector<int32_t>& ids);

    /**
     * @brief Gets a list of constraint source types for the specified os account.
     * @permission ohos.permission.MANAGE_LOCAL_ACCOUNTS
     * @param localId - Indicates the local ID of the OS account.
     * @param constraint - Indicates the constraint to query the source type.
     * @param constraintSourceTypeInfos - Indicates the list of constraint source types for the specified os account.
     * @return error code, see account_error_no.h
     */
    static ErrCode QueryOsAccountConstraintSourceTypes(const int32_t id, const std::string constraint,
        std::vector<ConstraintSourceTypeInfo> &constraintSourceTypeInfos);

    /**
     * @brief Sets the global constraints for all OS accounts.
     * @param constraints - Indicates the local IDs of all activated OS accounts.
     * @param isEnabled - Indicates whether the constraints are enabled.
     * @param enforcerId - Indicates the local ID of the OS account who enforce the operation.
     * @param isDeviceOwner - Indicates whether the enforcer is device owner.
     * @return error code, see account_error_no.h
     */
    static ErrCode SetGlobalOsAccountConstraints(const std::vector<std::string> &constraints,
        const bool isEnabled, const int32_t enforcerId = 0, const bool isDeviceOwner = false);

    /**
     * @brief Sets the constraints for the specified OS accounts.
     * @param constraints - Indicates the local IDs of all activated OS accounts.
     * @param enable - Indicates whether the constraints are enabled.
     * @param targetId - Indicates the local ID of the target OS account.
     * @param enforcerId - Indicates the local ID of the OS account who enforce the operation.
     * @param isDeviceOwner - Indicates whether the enforcer is device owner.
     * @return error code, see account_error_no.h
     */
    static ErrCode SetSpecificOsAccountConstraints(const std::vector<std::string> &constraints,
        const bool enable, const int32_t targetId, const int32_t enforcerId, const bool isDeviceOwner);

    /**
     * @brief Sets the default activated OS account.
     * @param id - Indicates the local IDs of the default activated OS accounts.
     * @return error code, see account_error_no.h
     */
    static ErrCode SetDefaultActivatedOsAccount(const int32_t id);

    /**
     * @brief Gets the default activated OS account.
     * @param id - Indicates the local IDs of the default activated OS accounts.
     * @return error code, see account_error_no.h
     */
    static ErrCode GetDefaultActivatedOsAccount(int32_t &id);

    /**
     * @brief Gets the currend user short name.
     * @param shortName - Indicates the current user short name of the OS account.
     * @return error code, see account_error_no.h
     */
    static ErrCode GetOsAccountShortName(std::string &shortName);

    /**
     * @brief Gets the currend user local name.
     * @param shortName - Indicates the current user local name of the OS account.
     * @return error code, see account_error_no.h
     */
    static ErrCode GetOsAccountName(std::string &name);

    /**
     * @brief Gets the user short name, based on account id.
     * @permission ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS
     * @param id - Indicates the local ID of the OS account.
     * @param shortName - Indicates the current user short name of the OS account.
     * @return error code, see account_error_no.h
     */
    static ErrCode GetOsAccountShortName(const int32_t id, std::string &shortName);

    /**
     * @brief Checks whether the current accoount is foreground.
     * @param isForeground - Indicates whether the specified localId is Foreground.
     * @return error code, see account_error_no.h
     */
    static ErrCode IsOsAccountForeground(bool &isForeground);

    /**
     * @brief Checks whether the specified accoount is foreground.
     * @param localId - Indicates the local Id of the OS account.
     * @param isForeground - Indicates whether the specified localId is foreground.
     * @return error code, see account_error_no.h
     */
    static ErrCode IsOsAccountForeground(const int32_t localId, bool &isForeground);

    /**
     * @brief Checks whether the specified accoount is foreground in specified display.
     * @param localId - Indicates the local id of the OS account.
     * @param displayId - Indicates the id of the display.
     * @param isForeground - Indicates whether the specified localId is foreground.
     * @return error code, see account_error_no.h
     */

    static ErrCode IsOsAccountForeground(const int32_t localId, const uint64_t displayId, bool &isForeground);

    /**
     * @brief Gets the id from default display.
     * @param localId - Indicates the corresponding localId of default display.
     * @return error code, see account_error_no.h
     */
    static ErrCode GetForegroundOsAccountLocalId(int32_t &localId);

    /**
     * @brief Gets the id from specified display.
     * @param displayId - Indicates the id of the specified display.
     * @param localId - Indicates the corresponding localId of specified display.
     * @return error code, see account_error_no.h
     */
    static ErrCode GetForegroundOsAccountLocalId(const uint64_t displayId, int32_t &localId);

    /**
     * @brief Gets the foreground accounts.
     * @param accounts - Indicates the foreground accounts.
     * @return error code, see account_error_no.h
     */
    static ErrCode GetForegroundOsAccounts(std::vector<ForegroundOsAccount> &accounts);

    /**
     * @brief Gets the foreground localId list.
     * @param localIds - Indicates the foreground localId list.
     * @return error code, see account_error_no.h
     */
    static ErrCode GetBackgroundOsAccountLocalIds(std::vector<int32_t> &localIds);

    /**
     * @brief Sets the target OS account to be removed or not.
     *
     * @permission ohos.permission.MANAGE_LOCAL_ACCOUNTS
     * @param localId - Indicates the target OS account.
     * @param toBeRemoved - Indicates whether the target OS account to be removed.
     * @return error code, see account_error_no.h
     */
    static ErrCode SetOsAccountToBeRemoved(int32_t localId, bool toBeRemoved);
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_OS_ACCOUNT_MANAGER_H
