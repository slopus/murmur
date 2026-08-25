export {
    addDeviceToRoster,
    createInitialDeviceRoster,
    decodeDeviceCredential,
    deviceRosterHash,
    encodeDeviceCredential,
    isActiveDevice,
    parseDeviceRoster,
    revokeDeviceFromRoster,
    selectDeviceRosterChild,
    serializeDeviceRoster,
    verifyDeviceRoster,
} from "./impl/deviceRosterCodec.js";
export {
    authorizeDeviceProvisioning,
    completeDeviceProvisioning,
    createDeviceLinkMaterial,
} from "./impl/deviceProvisioning.js";
export type {
    MurmurDeviceCredential,
    MurmurDeviceLinkMaterial,
    MurmurDeviceLinkRequest,
    MurmurDeviceProvisioningAuthorization,
    MurmurDeviceProvisioningEnvelope,
    MurmurDeviceRoster,
    MurmurDeviceRosterEntry,
    MurmurProvisionedAccount,
} from "./types.js";
