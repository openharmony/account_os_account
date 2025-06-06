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

#ifndef OS_ACCOUNT_FRAMEWORKS_OSACCOUNT_CORE_INCLUDE_OS_ACCOUNT_STUB_H
#define OS_ACCOUNT_FRAMEWORKS_OSACCOUNT_CORE_INCLUDE_OS_ACCOUNT_STUB_H

#include "ios_account.h"
#include "account_permission_manager.h"
#include "iremote_stub.h"

namespace OHOS {
namespace AccountSA {
class OsAccountStub : public IRemoteStub<IOsAccount> {
public:
    using MessageProcFunction = ErrCode (*)(OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply);
    typedef struct OsAccountMessageProc {
        MessageProcFunction messageProcFunction;
        bool isSystemApi = false;
    } OsAccountMessageProc;
    OsAccountStub();
    ~OsAccountStub() override;
    int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

public:
    ErrCode ProcCreateOsAccount(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcCreateOsAccountWithShortName(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcCreateOsAccountWithFullInfo(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcUpdateOsAccountWithFullInfo(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcRemoveOsAccount(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcSetOsAccountName(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcSetOsAccountConstraints(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcSetOsAccountProfilePhoto(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcQueryOsAccountById(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcQueryCurrentOsAccount(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcQueryAllCreatedOsAccounts(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcQueryMaxOsAccountNumber(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcQueryMaxLoggedInOsAccountNumber(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetCreatedOsAccountsCount(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetOsAccountAllConstraints(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetOsAccountLocalIdFromProcess(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcIsMainOsAccount(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetOsAccountProfilePhoto(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetOsAccountTypeFromProcess(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetOsAccountType(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetApplicationConstraints(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetApplicationConstraintsByNumber(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetOsAccountLocalIdBySerialNumber(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetSerialNumberByOsAccountLocalId(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcIsOsAccountActived(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcIsOsAccountConstraintEnable(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcCheckOsAccountConstraintEnabled(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcIsMultiOsAccountEnable(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcIsOsAccountVerified(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcIsOsAccountDeactivating(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcIsOsAccountExists(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcSubscribeOsAccount(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcUnsubscribeOsAccount(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcActivateOsAccount(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcDeactivateOsAccount(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcDeactivateAllOsAccounts(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcStartOsAccount(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcStopOsAccount(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetOsAccountSwitchMod(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcIsCurrentOsAccountVerified(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcIsOsAccountCompleted(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcSetCurrentOsAccountIsVerified(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcSetOsAccountIsVerified(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcDumpState(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetCreatedOsAccountNumFromDatabase(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetSerialNumberFromDatabase(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetMaxAllowCreateIdFromDatabase(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetOsAccountFromDatabase(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetOsAccountListFromDatabase(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcQueryActiveOsAccountIds(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcQueryOsAccountConstraintSourceTypes(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcSetGlobalOsAccountConstraints(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcSetSpecificOsAccountConstraints(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcSetDefaultActivatedOsAccount(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetDefaultActivatedOsAccount(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetOsAccountShortName(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetOsAccountName(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetOsAccountNameById(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetOsAccountShortNameById(MessageParcel &data, MessageParcel &reply);

    ErrCode ProcIsOsAccountForeground(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetForegroundOsAccountLocalId(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetForegroundOsAccounts(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetBackgroundOsAccountLocalIds(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcSetOsAccountToBeRemoved(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcCreateOsAccountForDomain(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetOsAccountLocalIdFromDomain(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetOsAccountDomainInfo(MessageParcel &data, MessageParcel &reply);
#ifdef SUPPORT_LOCK_OS_ACCOUNT
    ErrCode ProcPublishOsAccountLockEvent(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcLockOsAccount(MessageParcel &data, MessageParcel &reply);
#endif

private:
    bool WriteOsAccountInfoList(const std::vector<OsAccountInfo> &accounts, MessageParcel &data);
    DISALLOW_COPY_AND_MOVE(OsAccountStub);
    ErrCode ProcCheckOsAccountConstraintEnabled(uint32_t code, MessageParcel &data, MessageParcel &reply);
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_FRAMEWORKS_OSACCOUNT_CORE_INCLUDE_OS_ACCOUNT_STUB_H
