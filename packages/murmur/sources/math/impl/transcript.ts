import { concatBytes, utf8Encode } from "../../utils/index.js";
import { encodeUint16, lengthPrefix, protocolLabel } from "./codec.js";

const TRANSCRIPT_HEADER = utf8Encode("Murmur private-group transcript v1");

/** One named field in a canonical cryptographic transcript. */
export interface TranscriptField {
    readonly label: string;
    readonly value: Uint8Array;
}

/**
 * Encode a domain-separated, unambiguous transcript.
 *
 * Field labels are unique so callers cannot create two structural descriptions
 * with the same byte stream by regrouping repeated values.
 */
export function encodeTranscript(domain: string, fields: readonly TranscriptField[]): Uint8Array {
    const domainBytes = protocolLabel(domain);
    if (fields.length > 0xffff) {
        throw new Error("Transcript has too many fields");
    }
    const labels = new Set<string>();
    const encodedFields: Uint8Array[] = [];
    for (const field of fields) {
        if (labels.has(field.label)) {
            throw new Error(`Duplicate transcript field: ${field.label}`);
        }
        labels.add(field.label);
        encodedFields.push(lengthPrefix(protocolLabel(field.label)), lengthPrefix(field.value));
    }
    return concatBytes(
        lengthPrefix(TRANSCRIPT_HEADER),
        lengthPrefix(domainBytes),
        encodeUint16(fields.length),
        ...encodedFields,
    );
}
