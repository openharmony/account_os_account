/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

import { 
  testCreateOsAccountSync,
  testCreateOsAccountWithOptionSync,
  testActivateOsAccountSync,
  testGetActivatedOsAccountLocalIds,
  testGetForegroundOsAccountLocalId,
  testGetOsAccountLocalId,
  testGetOsAccountLocalIdForUid,
  testQueryCurrentOsAccountSync,
  testIsOsAccountUnlocked,
  testIsOsAccountUnlockedWithId,
  testQueryAllCreatedOsAccounts,
  testQueryMaxLoggedInOsAccountNumber,
  testQueryOsAccountById
} from "./test_accountmgr.ets";
import {
  testAddCredential,
  testDelUser
} from "./test_iam.ets";

export function createOsAccount() {
  testCreateOsAccountSync();
  testCreateOsAccountWithOptionSync();
}

export function activateOsAccount() {
  testActivateOsAccountSync();
}

export function deactivateOsAccount() {
  testActivateOsAccountSync();
}

export function getActivatedOsAccountLocalIds() {
  testGetActivatedOsAccountLocalIds();
}

export function getForegroundOsAccountLocalId() {
  testGetForegroundOsAccountLocalId();
}

export function getOsAccountLocalId() {
  testGetOsAccountLocalId();
}

export function getOsAccountLocalIdForUid() {
  testGetOsAccountLocalIdForUid();
}

export function queryCurrentOsAccount() {
  testQueryCurrentOsAccountSync();
}

export function isOsAccountUnlocked() {
  testIsOsAccountUnlocked();
  testIsOsAccountUnlockedWithId();
}

export function queryAllCreatedOsAccounts() {
  testQueryAllCreatedOsAccounts();
}

export function queryMaxLoggedInOsAccountNumber() {
  testQueryMaxLoggedInOsAccountNumber();
}

export function queryOsAccountById() {
  testQueryOsAccountById();
}

export function addCredential() {
  testAddCredential();
}

export function delUser() {
  testDelUser();
}
