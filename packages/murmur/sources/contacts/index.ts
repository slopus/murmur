export {
    contactSessionDescriptor,
    decodeContactPacket,
    decodeContactSessionDescriptor,
    encodeContactPacket,
    isContactSessionDescriptor,
    validateContactProfile,
} from "./impl/contactCodec.js";
export type {
    MurmurContact,
    MurmurContactAdded,
    MurmurContactPacket,
    MurmurContactProfile,
    MurmurContactProfileValue,
    MurmurContactRemoved,
    MurmurContactRequest,
    MurmurContactRequested,
} from "./types.js";
