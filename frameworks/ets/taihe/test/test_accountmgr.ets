/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
import osAccount from '@ohos.account.osAccount';
import { BusinessError } from '@ohos.base';
import { printOsAccountInfo } from './test_common.ets';

// createOsAccount(localName: string, type: OsAccountType, callback: AsyncCallback<OsAccountInfo>): void;
export function testCreateOsAccountSync(): void {
  console.log('[testCreateOsAccountSync] Start');
  let accountManager = osAccount.getAccountManager();
  let name: string = 'async_user_'+ Date.now();
  let type: osAccount.OsAccountType = osAccount.OsAccountType.NORMAL;
  accountManager.createOsAccount(name, type, (err: BusinessError | undefined, info: osAccount.OsAccountInfo | undefined) => {
    if (err) {
      console.error('[testCreateOsAccountSync] Error:', JSON.stringify(err));
    } else if (info) {
        console.log('[testCreateOsAccountWithOptionSync] Created account successfully');
        printOsAccountInfo(info);
    } else {
      console.error('[testCreateOsAccountSync] Unknown error: info is undefined');
    }
  });
}

// createOsAccount(localName: string, type: OsAccountType, options?: CreateOsAccountOptions): Promise<OsAccountInfo>;
export async function testCreateOsAccountWithOptionSync(): Promise<void> {
    console.log('[testCreateOsAccountWithOptionSync] Start');
    let accountManager = osAccount.getAccountManager();
    let name: string = 'option_user_' + Date.now();
    let type: osAccount.OsAccountType = osAccount.OsAccountType.NORMAL;
    let options: osAccount.CreateOsAccountOptions = { shortName: 'opt' + Date.now() };
    
    try {
      let info: osAccount.OsAccountInfo = await accountManager.createOsAccount(name, type, options);
      console.log('[testCreateOsAccountWithOptionSync] Created account successfully');
      printOsAccountInfo(info);
    } catch (err) {
      console.error('[testCreateOsAccountWithOptionSync] Error:', JSON.stringify(err));
    }
  }


// activateOsAccount(localId: int): Promise<void>;
// deactivateOsAccount(localId: int): Promise<void>;
export async function testActivateOsAccountSync(): Promise<void> {
  console.log('[testActivateOsAccountSync] Start');
  let accountManager = osAccount.getAccountManager();
  let info: osAccount.OsAccountInfo;
  
  try {
    let name: string = 'option_user_' + Date.now();
    let type: osAccount.OsAccountType = osAccount.OsAccountType.NORMAL;
    info = await accountManager.createOsAccount(name, type);
    await accountManager.activateOsAccount(info.localId);
    console.log('[testActivateOsAccountSync] Activated localId:', info.localId);
  } catch (err) {
    console.error('[testActivateOsAccountSync] Error:', JSON.stringify(err));
    return;
  }
  
  try {
    await accountManager.deactivateOsAccount(info.localId);
    console.log('[testDeactivateOsAccountSync] Deactivated localId:', info.localId);
  } catch (err) {
    console.error('[testDeactivateOsAccountSync] Error:', JSON.stringify(err));
  }
}

// getActivatedOsAccountLocalIds(): Promise<Array<int>>
export async function testGetActivatedOsAccountLocalIds(): Promise<void> {
  console.log('[testGetActivatedOsAccountLocalIds] Start');
  let accountManager = osAccount.getAccountManager();
  try {
    let ids: Array<int> = await accountManager.getActivatedOsAccountLocalIds();
    console.log('[testGetActivatedOsAccountLocalIds] Result:', JSON.stringify(ids));
  } catch (err) {
    console.error('[testGetActivatedOsAccountLocalIds] Error:', JSON.stringify(err));
  }
}

// getForegroundOsAccountLocalId(): Promise<int>
export async function testGetForegroundOsAccountLocalId(): Promise<void> {
  console.log('[testGetForegroundOsAccountLocalId] Start');
  let accountManager = osAccount.getAccountManager();
  try {
    let id: int = await accountManager.getForegroundOsAccountLocalId();
    console.log('[testGetForegroundOsAccountLocalId] Result:', id);
  } catch (err) {
    console.error('[testGetForegroundOsAccountLocalId] Error:', JSON.stringify(err));
  }
}

// getOsAccountLocalId(): Promise<int>
export async function testGetOsAccountLocalId(): Promise<void> {
  console.log('[testGetOsAccountLocalId] Start');
  let accountManager = osAccount.getAccountManager();
  try {
    let id: int = await accountManager.getOsAccountLocalId();
    console.log('[testGetOsAccountLocalId] Result:', id);
  } catch (err) {
    console.error('[testGetOsAccountLocalId] Error:', JSON.stringify(err));
  }
}

// getOsAccountLocalIdForUid(uid: int): Promise<int>
export async function testGetOsAccountLocalIdForUid(): Promise<void> {
    console.log('[testGetOsAccountLocalIdForUid] Start');
    let accountManager = osAccount.getAccountManager();
    let testUid: int = 20010015;
    try {
      let id: int = await accountManager.getOsAccountLocalIdForUid(testUid);
      console.log(`[testGetOsAccountLocalIdForUid] UID: ${testUid}, Result:`, id);
    } catch (err) {
      console.error('[testGetOsAccountLocalIdForUid] Error:', JSON.stringify(err));
    }
  }

// queryOsAccount(): Promise<OsAccountInfo>
export async function testQueryCurrentOsAccountSync(): Promise<void> {
  console.log('[testQueryCurrentOsAccountSync] Start');
  let accountManager = osAccount.getAccountManager();
  try {
    let info: osAccount.OsAccountInfo = await accountManager.queryOsAccount();
    console.log('[testQueryCurrentOsAccountSync] query account successfully');
    printOsAccountInfo(info);
  } catch (err) {
    console.error('[testQueryCurrentOsAccountSync] Error:', JSON.stringify(err));
  }
}

// isOsAccountUnlocked(): Promise<boolean>;
export async function testIsOsAccountUnlocked(): Promise<void> {
  console.log('[testIsOsAccountUnlocked] Start');
  let accountManager = osAccount.getAccountManager();
  try {
    let isUnlocked: boolean = await accountManager.isOsAccountUnlocked();
    console.log('[testIsOsAccountUnlocked] Result:', isUnlocked);
  } catch (err) {
    console.error('[testIsOsAccountUnlocked] Error:', JSON.stringify(err));
  }
}

// isOsAccountUnlocked(localId: int): Promise<boolean>;
export async function testIsOsAccountUnlockedWithId(): Promise<void> {
  console.log('[testIsOsAccountUnlockedWithId] Start');
  let accountManager = osAccount.getAccountManager();
  let info: osAccount.OsAccountInfo;
  try {
    let name: string = 'option_user_' + Date.now();
    let type: osAccount.OsAccountType = osAccount.OsAccountType.NORMAL;
    info = await accountManager.createOsAccount(name, type);
    let isUnlocked: boolean = await accountManager.isOsAccountUnlocked(info.localId);
    console.log(`[testIsOsAccountUnlockedWithId] Result for localId ${info.localId}:`, isUnlocked);
  } catch (err) {
    console.error('[testIsOsAccountUnlockedWithId] Error:', JSON.stringify(err));
  }
}

// queryAllCreatedOsAccounts(): Promise<Array<OsAccountInfo>>;
export async function testQueryAllCreatedOsAccounts(): Promise<void> {
  console.log('[testQueryAllCreatedOsAccounts] Start');
  let accountManager = osAccount.getAccountManager();
  try {
    let accounts: Array<osAccount.OsAccountInfo> = await accountManager.queryAllCreatedOsAccounts();
    console.log('[testQueryAllCreatedOsAccounts] Result:', JSON.stringify(accounts));
    for (let i = 0; i < accounts.length; i++) {
      printOsAccountInfo(accounts[i]);
    }
  } catch (err) {
    console.error('[testQueryAllCreatedOsAccounts] Error:', JSON.stringify(err));
  }
}

// queryMaxLoggedInOsAccountNumber(): Promise<int>;
export async function testQueryMaxLoggedInOsAccountNumber(): Promise<void> {
  console.log('[testQueryMaxLoggedInOsAccountNumber] Start');
  let accountManager = osAccount.getAccountManager();
  try {
    let maxNum: int = await accountManager.queryMaxLoggedInOsAccountNumber();
    console.log('[testQueryMaxLoggedInOsAccountNumber] Result:', maxNum);
  } catch (err) {
    console.error('[testQueryMaxLoggedInOsAccountNumber] Error:', JSON.stringify(err));
  }
}

// queryOsAccountById(localId: int): Promise<OsAccountInfo>;
export async function testQueryOsAccountById(): Promise<void> {
  console.log('[testQueryOsAccountById] Start');
  let accountManager = osAccount.getAccountManager();
  let info: osAccount.OsAccountInfo;
  try {
    let name: string = 'option_user_' + Date.now();
    let type: osAccount.OsAccountType = osAccount.OsAccountType.NORMAL;
    info = await accountManager.createOsAccount(name, type);
    let accountInfo: osAccount.OsAccountInfo = await accountManager.queryOsAccountById(info.localId);
    console.log('[testQueryOsAccountById] Result:', JSON.stringify(accountInfo));
    printOsAccountInfo(accountInfo);
  } catch (err) {
    console.error('[testQueryOsAccountById] Error:', JSON.stringify(err));
  }
}