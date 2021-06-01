# os\_account<a name="EN-US_TOPIC_0000001123681215"></a>

-   [Introduction](#section11660541593)
-   [Architecture](#section1412183212132)
-   [Directory Structure](#section161941989596)
-   [Usage](#section1312121216216)
    -   [Available APIs](#section1551164914237)

-   [Repositories Involved](#section1371113476307)

## Introduction<a name="section11660541593"></a>

In a standard system, the OS account module supports login status management of distributed cloud accounts, interconnection with vendors' cloud account apps on the device side, and query and update of the cloud account login status.

## Architecture<a name="section1412183212132"></a>

**Figure  1**  OS account architecture<a name="fig4460722185514"></a>


![](figures/en-us_image_0000001123704367.png)

## Directory Structure<a name="section161941989596"></a>

```
/base/account/os_account
├── common               # Common basic code
│   ├── account_error    # Error codes
│   ├── log              # Code for printing logs
│   ├── perf_stat        # Performance statistics
│   └── test             # Test code of common modules
├── interfaces           # APIs exposed externally
│   └── innerkits        # Header files for internal modules
├── kits                 # Development framework
├── sa_profile           # SA profile
├── services             # Service code
│   └── accountmgr       # Account manager service
└── test                 # Test code
    └── resource         # Test resources
```

## Usage<a name="section1312121216216"></a>

### Available APIs<a name="section1551164914237"></a>

The APIs available for distributed accounts can be called to query and update the account login status, and are supported only by system apps.

**Table  1**  Description of the distributed account module

<a name="table1650615420620"></a>
<table><thead align="left"><tr id="row175061254462"><th class="cellrowborder" valign="top" width="31.230000000000004%" id="mcps1.2.3.1.1"><p id="p1250613547612"><a name="p1250613547612"></a><a name="p1250613547612"></a>Module</p>
</th>
<th class="cellrowborder" valign="top" width="68.77%" id="mcps1.2.3.1.2"><p id="p85066541767"><a name="p85066541767"></a><a name="p85066541767"></a>Description</p>
</th>
</tr>
</thead>
<tbody><tr id="row0506185417614"><td class="cellrowborder" valign="top" width="31.230000000000004%" headers="mcps1.2.3.1.1 "><p id="p1561112131788"><a name="p1561112131788"></a><a name="p1561112131788"></a>distributedAccount</p>
</td>
<td class="cellrowborder" valign="top" width="68.77%" headers="mcps1.2.3.1.2 "><p id="p1954531161115"><a name="p1954531161115"></a><a name="p1954531161115"></a>Provides methods for managing the distributed account module.</p>
</td>
</tr>
</tbody>
</table>

**Table  2**  Classes for distributed accounts

<a name="table1324102194217"></a>
<table><thead align="left"><tr id="row43241021174219"><th class="cellrowborder" valign="top" width="51.61%" id="mcps1.2.3.1.1"><p id="p10324621104214"><a name="p10324621104214"></a><a name="p10324621104214"></a>Class</p>
</th>
<th class="cellrowborder" valign="top" width="48.39%" id="mcps1.2.3.1.2"><p id="p2324221174213"><a name="p2324221174213"></a><a name="p2324221174213"></a>Description</p>
</th>
</tr>
</thead>
<tbody><tr id="row1432413213425"><td class="cellrowborder" valign="top" width="51.61%" headers="mcps1.2.3.1.1 "><p id="p1732472184212"><a name="p1732472184212"></a><a name="p1732472184212"></a>DistributedAccountAbility</p>
</td>
<td class="cellrowborder" valign="top" width="48.39%" headers="mcps1.2.3.1.2 "><p id="p1932432110421"><a name="p1932432110421"></a><a name="p1932432110421"></a>Provides methods for querying and updating the login status of distributed accounts.</p>
</td>
</tr>
<tr id="row12324162116427"><td class="cellrowborder" valign="top" width="51.61%" headers="mcps1.2.3.1.1 "><p id="p1232422184216"><a name="p1232422184216"></a><a name="p1232422184216"></a>DistributedInfo</p>
</td>
<td class="cellrowborder" valign="top" width="48.39%" headers="mcps1.2.3.1.2 "><p id="p1324821164215"><a name="p1324821164215"></a><a name="p1324821164215"></a>Provides methods for querying distributed account information, including the account name, UID, and login status.</p>
</td>
</tr>
</tbody>
</table>

**Table  3**  Methods for the distributed account module

<a name="table6561120114219"></a>
<table><thead align="left"><tr id="row115642084211"><th class="cellrowborder" valign="top" width="51.67%" id="mcps1.2.3.1.1"><p id="p7565201424"><a name="p7565201424"></a><a name="p7565201424"></a>Method</p>
</th>
<th class="cellrowborder" valign="top" width="48.33%" id="mcps1.2.3.1.2"><p id="p0568204427"><a name="p0568204427"></a><a name="p0568204427"></a>Description</p>
</th>
</tr>
</thead>
<tbody><tr id="row456162064218"><td class="cellrowborder" valign="top" width="51.67%" headers="mcps1.2.3.1.1 "><p id="p8388718174317"><a name="p8388718174317"></a><a name="p8388718174317"></a>function getDistributedAccountAbility(): DistributedAccountAbility</p>
</td>
<td class="cellrowborder" valign="top" width="48.33%" headers="mcps1.2.3.1.2 "><p id="p5561920194211"><a name="p5561920194211"></a><a name="p5561920194211"></a>Obtains a singleton of a distributed account.</p>
</td>
</tr>
</tbody>
</table>

**Table  4**  DistributedAccountAbility description

<a name="table1738121244713"></a>
<table><thead align="left"><tr id="row4381111254710"><th class="cellrowborder" valign="top" width="31.209999999999997%" id="mcps1.2.3.1.1"><p id="p1738116127470"><a name="p1738116127470"></a><a name="p1738116127470"></a>Method</p>
</th>
<th class="cellrowborder" valign="top" width="68.78999999999999%" id="mcps1.2.3.1.2"><p id="p10381161224717"><a name="p10381161224717"></a><a name="p10381161224717"></a>Description</p>
</th>
</tr>
</thead>
<tbody><tr id="row18381121274715"><td class="cellrowborder" valign="top" width="31.209999999999997%" headers="mcps1.2.3.1.1 "><p id="p1671817233812"><a name="p1671817233812"></a><a name="p1671817233812"></a>queryOsAccountDistributedInfo(callback: AsyncCallback&lt;DistributedInfo&gt;): void</p>
</td>
<td class="cellrowborder" valign="top" width="68.78999999999999%" headers="mcps1.2.3.1.2 "><p id="p63421233134612"><a name="p63421233134612"></a><a name="p63421233134612"></a>Queries information about the distributed account.</p>
</td>
</tr>
<tr id="row1938113125470"><td class="cellrowborder" valign="top" width="31.209999999999997%" headers="mcps1.2.3.1.1 "><p id="p73429332466"><a name="p73429332466"></a><a name="p73429332466"></a>queryOsAccountDistributedInfo(): Promise&lt;DistributedInfo&gt;</p>
</td>
<td class="cellrowborder" valign="top" width="68.78999999999999%" headers="mcps1.2.3.1.2 "><p id="p7342133394620"><a name="p7342133394620"></a><a name="p7342133394620"></a>Queries information about the distributed account.</p>
</td>
</tr>
<tr id="row13811912164716"><td class="cellrowborder" valign="top" width="31.209999999999997%" headers="mcps1.2.3.1.1 "><p id="p186182593814"><a name="p186182593814"></a><a name="p186182593814"></a>updateOsAccountDistributedInfo(accountInfo: DistributedInfo, callback: AsyncCallback&lt;boolean&gt;): void</p>
</td>
<td class="cellrowborder" valign="top" width="68.78999999999999%" headers="mcps1.2.3.1.2 "><p id="p1534263304617"><a name="p1534263304617"></a><a name="p1534263304617"></a>Updates information about the distributed account.</p>
</td>
</tr>
<tr id="row10382181218477"><td class="cellrowborder" valign="top" width="31.209999999999997%" headers="mcps1.2.3.1.1 "><p id="p686934433810"><a name="p686934433810"></a><a name="p686934433810"></a>updateOsAccountDistributedInfo(accountInfo: DistributedInfo): Promise&lt;boolean&gt;</p>
</td>
<td class="cellrowborder" valign="top" width="68.78999999999999%" headers="mcps1.2.3.1.2 "><p id="p0342193384611"><a name="p0342193384611"></a><a name="p0342193384611"></a>Updates information about the distributed account.</p>
</td>
</tr>
</tbody>
</table>

## Repositories Involved<a name="section1371113476307"></a>

Account subsystem

**account\_os\_account**

