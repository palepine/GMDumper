# Initialization, status, version, and profiles

## Initialization

#### `gm_initDumper(options)`
> Initialize the dumper (scanner)
> runtime state or `nil, errMsg`.

```lua
assert( gm_initDumper() )
```

| Option | Default | Description |
|---|---:|---|
| `minimumFunctionCount` | `32` | Minimum validated built-ins required |
| `scanScripts` | `true` | Search for native YYC script metadata |
| `maximumScripts` | `4096` | Maximum native scripts to return |
| `scanInstances` | `true` | Discover the current room and active instances |
| `instanceScanTimeoutMs` | `15000` | Instance-discovery deadline |
| `maximumInstances` | `100000` | Maximum active instances to accept |
| `maximumRawVariables` | `4096` | Maximum fields returned per query |
| `maximumVariableMapBuckets` | `1048576` | Reject implausibly large sparse maps |
| `rawVariableSlots` | `64` | Dense slots displayed in Structure Dissect |
| `rawVariableMapBuckets` | `64` | Sparse buckets displayed in Structure Dissect |
| `fieldRefreshInterval` | `250` | Symbol refresh interval in milliseconds; minimum 100 |
| `bridge` | `true` | Load the bridge |
| `bridgeTimeout` | `5000` | Bridge request timeout |

    Overrides are also accepted: `functionTableAddress`, `functionEntryKind`, `codeExecuteAddress`, `runRoomAddress`,
    `roomActiveListOffset`, `instanceMembersOffset`, `instanceFlinkOffset`, `instanceMotionOffsetShift`

## Status

#### `gm_getStatus()`
> Get dumper status table.

```lua
local status = gm_getStatus()
print( status.ready, status.runnerKind, status.instancesAvailable, status.namedReflection )
print( status.lastError or status.bridgeError )
print( status.log )
```

| Field | Description |
|---|---|
| `ready` | Runtime scan completed successfully |
| `scanning` | Initialization is still running |
| `lastError` | Last initialization error |
| `log` | logs for the current scan |
| `runnerKind` | `VM`, `YYC`, mixed capability result |
| `version` | Selected version descriptor |
| `profile` | Runner/bridge profile |
| `functionCount` | Discovered built-in count |
| `scriptCount` | Discovered native YYC script count |
| `instancesAvailable` | Current-room instance layout validated |
| `instanceCount` | Active instance count |
| `instanceError` | Instance discovery err |
| `namedReflection` | Bridge/legacy runtime registry can resolve gameplay-field names |
| `reflectionError` | Reflection means error |
| `bridgeError` | Bridge loading/discovery failure |

#### `gm_getState()`
> Return runtime state.

#### `gm_getLayout()`
> Return the validated function, room, instance layouts.

```lua
local layout = gm_getLayout()
print( layout.pointerSize, layout.functionEntryKind, layout.functionEntrySize )
print( layout.functionTable or layout.functionRegistrar )
print( layout.codeExecute, layout.runRoom )
```

#### `gm_getVersion()`
> Return the selected version with info.

#### `gm_getProfile()`
> Return the selected version profile.

```lua
local profile = gm_getProfile()
print( profile.id, profile.architecture, profile.bridge.id )
```

## Bridge

#### `gm_getBridgeStatus()`
> Return bridge status/info

#### `gm_configureBridge(reflection)`
> Retry bridge configuration.

    Notes: omit passing anything for normal profiled inference.
    Supply confirmed addresses if auto-inference fails

```lua
assert( gm_configureBridge() )

-- overridoing
assert( gm_configureBridge { structGetKeys = 0x140000000 , structGetMember = 0x140000000 } )
```