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

// addCredential(credentialInfo: CredentialInfo, callback: IIdmCallback): void;
export function testAddCredential(): void {
  console.log('[testAddCredential] Start');
  
  try {
    let userIdentityManager = new osAccount.UserIdentityManager();
    let token: Uint8Array = new Uint8Array([1, 2, 3, 4, 5, 6]);

    let credentialInfo: osAccount.CredentialInfo = {
      credType: osAccount.AuthType.PIN,
      credSubType: osAccount.AuthSubType.PIN_SIX,
      token: token,
      accountId: 100
    };
    
    let callback: osAccount.IIdmCallback = {
      onResult: (result: int, extraInfo: osAccount.RequestResult) => {
        console.log(`[testAddCredential] onResult called with result: ${result}`);
        if (result === 0) {
          console.log('[testAddCredential] Add credential succeeded');
          if (extraInfo.credentialId) {
            console.log(`[testAddCredential] Credential ID: ${extraInfo.credentialId}`);
          }
        } else {
          console.error(`[testAddCredential] Add credential failed with error: ${result}`);
        }
      },
      onAcquireInfo: (module: int, acquire: int, extraInfo: Uint8Array) => {
        console.log(`[testAddCredential] onAcquireInfo called: module=${module}, acquire=${acquire}, extraInfo=${extraInfo}`);
      }
    };
    
    userIdentityManager.addCredential(credentialInfo, callback);
    console.log('[testAddCredential] addCredential request sent');
  } catch (err) {
    console.error(`[testAddCredential] Error: ${JSON.stringify(err)}`);
  }
}

// delUser(token: Uint8Array, callback: IIdmCallback): void;
export function testDelUser(): void {
  console.log('[testDelUser] Start');
  
  try {
    let userIdentityManager = new osAccount.UserIdentityManager();
    let token: Uint8Array = new Uint8Array([10, 20, 30, 40, 50, 60, 70, 80]);

    let callback: osAccount.IIdmCallback = {
      onResult: (result: int, extraInfo: osAccount.RequestResult) => {
        console.log(`[testDelUser] onResult called with result: ${result}`);
        if (result === 0) {
          console.log('[testDelUser] Delete user succeeded');
        } else {
          console.error(`[testDelUser] Delete user failed with error: ${result}`);
        }
      },
      onAcquireInfo: (module: int, acquire: int, extraInfo: Uint8Array) => {
        console.log(`[testDelUser] onAcquireInfo called: module=${module}, acquire=${acquire}, extraInfo=${extraInfo}`);
      }
    };

    userIdentityManager.delUser(token, callback);
    console.log('[testDelUser] delUser request sent');
  } catch (err) {
    console.error(`[testDelUser] Error: ${err}`);
  }
}