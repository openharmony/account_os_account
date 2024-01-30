/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
 * @addtogroup AppAccount
 * @{
 *
 * @brief Provides app account management.
 *
 * Provides the capability to manage application accounts.
 *
 * @since 7.0
 * @version 7.0
 */

/**
 * @file app_account_manager.h
 *
 * @brief Declares app account manager interfaces.
 *
 * @since 7.0
 * @version 7.0
 */
#ifndef APP_ACCOUNT_INTERFACES_INNERKITS_APPACCOUNT_NATIVE_INCLUDE_APP_ACCOUNT_MANAGER_H
#define APP_ACCOUNT_INTERFACES_INNERKITS_APPACCOUNT_NATIVE_INCLUDE_APP_ACCOUNT_MANAGER_H

#include "app_account_subscriber.h"
#include "app_account_common.h"
#include "app_account_info.h"
#include "iapp_account_authenticator_callback.h"
#include "iremote_object.h"

namespace OHOS {
namespace AccountSA {
class AppAccountManager {
public:
    /**
     * @brief Adds the account name and extra information of this application to the account management service.
     * <p>
     * Only the owner of the application account has the permission to call this method.
     * @param name - Indicates the name of the application account to add.
     * @param extraInfo - Indicates the extra information of the application account to add.
     *        The extra information cannot be sensitive information of the application account.
     * @return error code, see account_error_no.h
     */
    static ErrCode AddAccount(const std::string &name, const std::string &extraInfo = "");

    /**
     * @brief Adds an application account of a specified owner implicitly.
     * @param owner - Indicates the account owner of your application or third-party applications.
     * @param authType - Indicates the authentication type.
     * @param options - Indicates the authenticator-specific options for the request.
     * @param callback - Indicates the callback for get result.
     * @return error code, see account_error_no.h
     */
    static ErrCode AddAccountImplicitly(const std::string &owner, const std::string &authType,
        const AAFwk::Want &options, const sptr<IAppAccountAuthenticatorCallback> &callback);

    /**
     * @brief Creates the account name and extra information of this application to the account management service.
     * <p>
     * Only the owner of the application account has the permission to call this method.
     * @param name - Indicates the name of the application account to add.
     * @param options - Indicates the extra information of the application account to add.
     *        The extra information cannot be sensitive information of the application account.
     * @return account error, see account_error_no.h
     */
    static ErrCode CreateAccount(const std::string &name, const CreateAccountOptions &options);

    /**
     * @brief Creates an application account of a specified owner implicitly.
     * @param owner - Indicates the account owner of your application or third-party applications.
     * @param callback - Indicates the authenticator callback.
     * @return account error, see account_error_no.h
     */
    static ErrCode CreateAccountImplicitly(const std::string &owner, const CreateAccountImplicitlyOptions &options,
        const sptr<IAppAccountAuthenticatorCallback> &callback);

    /**
     * @brief Deletes an application account from the account management service.
     * <p>
     * Only the owner of the application account has the permission to call this method.
     * @param name - Indicates the name of the application account to delete.
     * @return account error, see account_error_no.h
     */
    static ErrCode DeleteAccount(const std::string &name);

    /**
     * @brief Gets extra information of this application account.
     * @param name - Indicates the name of the application account.
     * @param extraInfo - Indicates the extra information of the account.
     * @return account error, see account_error_no.h
     */
    static ErrCode GetAccountExtraInfo(const std::string &name, std::string &extraInfo);

    /**
     * @brief Sets extra information for this application account.
     * <p>
     * You can call this method when you forget the extra information of your application account or
     * need to modify the extra information.
     * @param name - Indicates the name of the application account.
     * @param extraInfo - Indicates the extra information to set.
     * @return account error, see account_error_no.h
     */
    static ErrCode SetAccountExtraInfo(const std::string &name, const std::string &extraInfo);

    /**
     * @brief Enables a third-party application with the specified bundle name to access the given application
     * account for data query and listening.
     * @param name - Indicates the name of the application account.
     * @param authorizedApp - Indicates the bundle name of the third-party application.
     * @return account error, see account_error_no.h
     */
    static ErrCode EnableAppAccess(const std::string &name, const std::string &authorizedApp);

    /**
     * @brief Disables a third-party application with the specified bundle name from
     * accessing the given application account.
     * @param name - Indicates the name of the application account to disable access from
     *        the third-party application.
     * @param bundleName - Indicates the bundle name of the third-party application.
     * @return account error, see account_error_no.h
     */
    static ErrCode DisableAppAccess(const std::string &name, const std::string &authorizedApp);

    /**
     * @brief Sets a third-party application with the specified bundle name to access the given application
     * account for data query and listening.
     * @param name - Indicates the name of the application account.
     * @param bundleName - Indicates the bundle name of the third-party application.
     * @param isAccessible - Indicates whether the account is accessible for the specified application.
     * @return account error, see account_error_no.h
     */
    static ErrCode SetAppAccess(const std::string &name, const std::string &authorizedApp, bool isAccessible);

    /**
     * @brief Checks whether a specified application account allows application data synchronization.
     * <p>
     * If the same OHOS account has logged in to multiple devices, these devices constitute a super device
     * through the distributed networking. On the connected devices, you can call this method to check
     * whether application data can be synchronized.
     * <p>
     * @permission ohos.permission.DISTRIBUTED_DATASYNC
     * @param name - Indicates the name of the application account.
     * @param syncEnable - Indicates whether the data sync is enabled.
     * @return account error, see account_error_no.h
     */
    static ErrCode CheckAppAccountSyncEnable(const std::string &name, bool &syncEnable);

    /**
     * @brief Sets whether a specified application account allows application data synchronization.
     * <p>
     * If the same OHOS account has logged in to multiple devices, these devices constitute a super device
     * through the distributed networking. On the connected devices, you can call this method to set whether to
     * allow cross-device data synchronization. If synchronization is allowed, application data can be synchronized
     * among these devices in the event of any changes related to the application account.
     * If synchronization is not allowed, the application data is stored only on the local device.
     * <p>
     * <b>Application account-related changes</b>: adding or deleting an application account, setting extra
     * information (such as updating a token), and setting data associated with this application account
     * <p>
     * <b>Application data that can be synchronized</b>: application account name, token,
     * and data associated with this application account
     * <p>
     * @permission ohos.permission.DISTRIBUTED_DATASYNC
     * @param name - Indicates the name of the application account.
     * @param syncEnable - Specifies whether to allow application data synchronization.
     * @return account error, see account_error_no.h
     */
    static ErrCode SetAppAccountSyncEnable(const std::string &name, const bool &syncEnable);

    /**
     * @brief Gets data associated with this application account.
     * @param name - Indicates the name of the application account.
     * @param key - Indicates the key of the data.
     * @param value - Indicates the value of the data.
     * @return account error, see account_error_no.h
     */
    static ErrCode GetAssociatedData(const std::string &name, const std::string &key, std::string &value);

    /**
     * @brief Sets data associated with this application account.
     * @param name - Indicates the name of the application account.
     * @param key - Indicates the key of the data to set. The key can be customized.
     * @param value - Indicates the value of the data to set.
     * @return account error, see account_error_no.h
     */
    static ErrCode SetAssociatedData(const std::string &name, const std::string &key, const std::string &value);

    /**
     * @brief Gets the credential of this application account.
     * @param name - Indicates the name of the application account.
     * @param credentialType - Indicates the type of the credential to obtain.
     * @param credential - Indicates the credential of the application account.
     * @return account error, see account_error_no.h
     */
    static ErrCode GetAccountCredential(
        const std::string &name, const std::string &credentialType, std::string &credential);

    /**
     * @brief Sets the credential for this application account.
     * @param name - Indicates the name of the application account.
     * @param credentialType - Indicates the type of the credential to set.
     * @param credential - Indicates the credential to set.
     * @return account error, see account_error_no.h
     */
    static ErrCode SetAccountCredential(
        const std::string &name, const std::string &credentialType, const std::string &credential);

    /**
     * @brief Authenticates an application account to get an oauth token.
     * @param name - Indicates the account name of your application or third-party applications.
     * @param owner - Indicates the account owner of your application or third-party applications.
     * @param authType - Indicates the authentication type.
     * @param options - Indicates the authenticator-specific options for the request.
     * @param callback - Indicates the authenticator callback.
     * @return account error, see account_error_no.h
     */
    static ErrCode Authenticate(const std::string &name, const std::string &owner, const std::string &authType,
        const AAFwk::Want &options, const sptr<IAppAccountAuthenticatorCallback> &callback);

    /**
     * @brief Gets an oauth token with the specified authentication type from a particular application account.
     * @param name - Indicates the account name of your application or third-party applications.
     * @param owner - Indicates the account owner of your application or third-party applications.
     * @param authType - Indicates the authentication type.
     * @param token - Indicates the auth token.
     * @return account error, see account_error_no.h
     */
    static ErrCode GetOAuthToken(const std::string &name, const std::string &owner, const std::string &authType,
        std::string &token);

    /**
     * @brief Gets an oauth token with the specified authentication type from a particular application account.
     * @param name - Indicates the account name of your application or third-party applications.
     * @param owner - Indicates the account owner of your application or third-party applications.
     * @param authType - Indicates the authentication type.
     * @param token - Indicates the auth token.
     * @return account error, see account_error_no.h
     */
    static ErrCode GetAuthToken(const std::string &name, const std::string &owner, const std::string &authType,
        std::string &token);

    /**
     * @brief Sets an oauth token with the specified authentication type for a particular account.
     * <p>
     * Only the owner of the application account has the permission to call this method.
     * @param name - Indicates the account name of your application.
     * @param authType - Indicates the authentication type.
     * @param token - Indicates the oauth token.
     * @return account error, see account_error_no.h
     */
    static ErrCode SetOAuthToken(
        const std::string &name, const std::string &authType, const std::string &token);

    /**
     * @brief Deletes an oauth token for the specified application account.
     * <p>
     * Only tokens visible to the caller application can be deleted.
     * @param name - Indicates the account name of your application or third-party applications.
     * @param owner - Indicates the account owner of your application or third-party applications.
     * @param authType - Indicates the authentication type.
     * @param token - Indicates the oauth token.
     * @return account error, see account_error_no.h
     */
    static ErrCode DeleteOAuthToken(
        const std::string &name, const std::string &owner, const std::string &authType, const std::string &token);

    /**
     * @brief Deletes an oauth token for the specified application account.
     * <p>
     * Only tokens visible to the caller application can be deleted.
     * @param name - Indicates the account name of your application or third-party applications.
     * @param owner - Indicates the account owner of your application or third-party applications.
     * @param authType - Indicates the authentication type.
     * @param token - Indicates the oauth token.
     * @return account error, see account_error_no.h
     */
    static ErrCode DeleteAuthToken(
        const std::string &name, const std::string &owner, const std::string &authType, const std::string &token);

    /**
     * @brief Sets the oauth token visibility of the specified authentication type to a third-party application.
     * <p>
     * Only the owner of the application account has the permission to call this method.
     * @param name - Indicates the account name of your application.
     * @param authType - Indicates the authentication type.
     * @param bundleName - Indicates the bundle name of the third-party application.
     * @param isVisible - Indicates the bool value of visibility.
     * @return account error, see account_error_no.h
     */
    static ErrCode SetOAuthTokenVisibility(const std::string &name, const std::string &authType,
        const std::string &bundleName, bool isVisible);

    /**
     * @brief Sets the oauth token visibility of the specified authentication type to a third-party application.
     * <p>
     * Only the owner of the application account has the permission to call this method.
     * @param name - Indicates the account name of your application.
     * @param authType - Indicates the authentication type.
     * @param bundleName - Indicates the bundle name of the third-party application.
     * @param isVisible - Indicates the bool value of visibility.
     * @return account error, see account_error_no.h
     */
    static ErrCode SetAuthTokenVisibility(const std::string &name, const std::string &authType,
        const std::string &bundleName, bool isVisible);

    /**
     * @brief Checks the oauth token visibility of the specified authentication type for a third-party application.
     * <p>
     * Only the owner of the application account has the permission to call this method.
     * @param name - Indicates the account name of your application or third-party applications.
     * @param authType - Indicates the authentication type.
     * @param bundleName - Indicates the bundle name of the third-party application.
     * @param isVisible - Indicates the bool value of visibility.
     * @return account error, see account_error_no.h
     */
    static ErrCode CheckOAuthTokenVisibility(const std::string &name, const std::string &authType,
        const std::string &bundleName, bool &isVisible);

    /**
     * @brief Checks the oauth token visibility of the specified authentication type for a third-party application.
     * <p>
     * Only the owner of the application account has the permission to call this method.
     * @param name - Indicates the account name of your application or third-party applications.
     * @param authType - Indicates the authentication type.
     * @param bundleName - Indicates the bundle name of the third-party application.
     * @param isVisible - Indicates the bool value of visibility.
     * @return account error, see account_error_no.h
     */
    static ErrCode CheckAuthTokenVisibility(const std::string &name, const std::string &authType,
        const std::string &bundleName, bool &isVisible);

    /**
     * @brief Gets the authenticator information of an application account.
     * @param owner - Indicates the account owner of your application or third-party applications.
     * @param info - Indicates the authenticator information of the application account.
     * @return account error, see account_error_no.h
     */
    static ErrCode GetAuthenticatorInfo(const std::string &owner, AuthenticatorInfo &info);

    /**
     * @brief Gets all oauth tokens visible to the caller application.
     * @param name - Indicates the account name of your application or third-party applications.
     * @param owner - Indicates the account owner of your application or third-party applications.
     * @param tokenInfos - Indicates the list of token.
     * @return account error, see account_error_no.h
     */
    static ErrCode GetAllOAuthTokens(const std::string &name, const std::string &owner,
        std::vector<OAuthTokenInfo> &tokenInfos);

    /**
     * @brief Gets the open authorization list with a specified authentication type
     * for a particular application account.
     * <p>
     * Only the owner of the application account has the permission to call this method.
     * @param name - Indicates the account name of your application.
     * @param authType - Indicates the authentication type.
     * @param oauthList - Indicates the open authorization list of the specified authentication type.
     * @return account error, see account_error_no.h
     */
    static ErrCode GetOAuthList(const std::string &name, const std::string &authType,
        std::set<std::string> &oauthList);

    /**
     * @brief Gets the open authorization list with a specified authentication type
     * for a particular application account.
     * <p>
     * Only the owner of the application account has the permission to call this method.
     * @param name - Indicates the account name of your application.
     * @param authType - Indicates the authentication type.
     * @param authList - Indicates the open authorization list of the specified authentication type.
     * @return account error, see account_error_no.h
     */
    static ErrCode GetAuthList(const std::string &name, const std::string &authType,
        std::set<std::string> &oauthList);

    /**
     * @brief Gets the authenticator callback with the specified session id.
     * <p>
     * Only the owner of the authenticator has the permission to call this method.
     * @param sessionId - Indicates the id of a authentication session.
     * @param callback - Indicates the authenticator callback related to the session id.
     * @return account error, see account_error_no.h
     */
    static ErrCode GetAuthenticatorCallback(const std::string &sessionId, sptr<IRemoteObject> &callback);

    /**
     * @brief Gets information about all accounts of a specified account owner.
     * <p>
     * This method applies to the following accounts:
     * <ul>
     * <li>Accounts of this application.</li>
     * <li>Accounts of third-party applications. To obtain such information,
     * your application must have gained authorization from the third-party applications or
     * have gained the ohos.permission.GET_ALL_APP_ACCOUNTS permission.</li>
     * </ul>
     * @permission ohos.permission.GET_ALL_APP_ACCOUNTS
     * @param  owner - Indicates the account owner of your application or third-party applications.
     * @param appAccounts - Indicates a list of application accounts.
     * @return account error, see account_error_no.h
     */
    static ErrCode GetAllAccounts(const std::string &owner, std::vector<AppAccountInfo> &appAccounts);

    /**
     * @brief Gets information about all accessible accounts.
     * <p>
     * This method applies to the following accounts:
     * <ul>
     * <li>Accounts of this application.</li>
     * <li>Accounts of third-party applications. To obtain such information,
     * your application must have gained authorization from the third-party applications or
     * have gained the ohos.permission.GET_ALL_APP_ACCOUNTS permission.</li>
     * </ul>
     * @permission ohos.permission.GET_ALL_APP_ACCOUNTS
     * @param appAccounts - Indicates a list of application accounts.
     * @return account error, see account_error_no.h
     */
    static ErrCode GetAllAccessibleAccounts(std::vector<AppAccountInfo> &appAccounts);

    /**
     * @brief Gets information about all accounts of a specified account owner.
     * <p>
     * This method applies to the following accounts:
     * <ul>
     * <li>Accounts of this application.</li>
     * <li>Accounts of third-party applications. To obtain such information,
     * your application must have gained authorization from the third-party applications or
     * have gained the ohos.permission.GET_ALL_APP_ACCOUNTS permission.</li>
     * </ul>
     * @permission ohos.permission.GET_ALL_APP_ACCOUNTS
     * @param  owner - Indicates the account owner of your application or third-party applications.
     * @param appAccounts - Indicates a list of application accounts.
     * @return account error, see account_error_no.h
     */
    static ErrCode QueryAllAccessibleAccounts(const std::string &owner, std::vector<AppAccountInfo> &appAccounts);

    /**
     * @brief Checks whether a third-party application with the specified bundle name is allowed to access
     * the given application account for data query and listening.
     * @param name - Indicates the name of the application account.
     * @param bundleName - Indicates the bundle name of the third-party application.
     * @param isAccessible - Indicates whether the account is accessible for the specified application.
     * @return account error, see account_error_no.h
     */
    static ErrCode CheckAppAccess(const std::string &name, const std::string &authorizedApp, bool &isAccessible);

    /**
     * @brief Deletes the credential of the specified application account.
     * @param name - Indicates the account name.
     * @param credentialType - Indicates the type of the credential to delete.
     * @return account error, see account_error_no.h
     */
    static ErrCode DeleteAccountCredential(const std::string &name, const std::string &credentialType);

    /**
     * @brief Selects a list of accounts that satisfied with the specified options.
     * @param options - Indicates the options for selecting account.
     * @param callback - Indicates the authenticator callback.
     * @return account error, see account_error_no.h
     */
    static ErrCode SelectAccountsByOptions(
        const SelectAccountsOptions &options, const sptr<IAppAccountAuthenticatorCallback> &callback);

    /**
     * @brief Verifies the credential to ensure the user is the owner of the specified account.
     * @param name - Indicates the account name.
     * @param owner - Indicates the account owner.
     * @param callback - Indicates the authenticator callback.
     * @return account error, see account_error_no.h
     */
    static ErrCode VerifyCredential(const std::string &name, const std::string &owner,
        const VerifyCredentialOptions &options, const sptr<IAppAccountAuthenticatorCallback> &callback);

    /**
     * @brief Checks whether a particular account has all specified labels.
     * @param name - Indicates the account name.
     * @param labels - Indicates an array of labels to check.
     * @param callback - Indicates the authenticator callback.
     * @return account error, see account_error_no.h
     */
    static ErrCode CheckAccountLabels(const std::string &name, const std::string &owner,
        const std::vector<std::string> &labels, const sptr<IAppAccountAuthenticatorCallback> &callback);

    /**
     * @brief Sets properties for the specified account authenticator.
     * <p>
     * If the authenticator supports setting its properties,
     * the caller will normally be redirected to an Ability specified by Want for property setting.
     * @param owner - Indicates the owner of authenticator.
     * @param callback - Indicates the authenticator callback.
     * @return account error, see account_error_no.h
     */
    static ErrCode SetAuthenticatorProperties(const std::string &owner,
        const SetPropertiesOptions &options, const sptr<IAppAccountAuthenticatorCallback> &callback);

    /**
     * @brief Subscribes to the change events of accounts of the specified owners.
     * <p>
     * When the account owner updates the account, the subscriber will receive a notification
     * about the account change event.
     * @param subscriber - Indicates the subscriber information.
     * @return account error, see account_error_no.h
     */
    static ErrCode SubscribeAppAccount(const std::shared_ptr<AppAccountSubscriber> &subscriber);

    /**
     * @brief Unsubscribes from account events.
     * @param subscriber - Indicates the subscriber information.
     * @return account error, see account_error_no.h
     */
    static ErrCode UnsubscribeAppAccount(const std::shared_ptr<AppAccountSubscriber> &subscriber);
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // APP_ACCOUNT_INTERFACES_INNERKITS_APPACCOUNT_NATIVE_INCLUDE_APP_ACCOUNT_MANAGER_H
