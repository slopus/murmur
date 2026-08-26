import { ed25519 } from "@noble/curves/ed25519";
import { randomBytes } from "@noble/hashes/utils";
import { decodeBase64Url, encodeBase64Url } from "../../utils/base64Url.js";
import { canonicalJson } from "../../utils/canonicalJson.js";
import { parseStrictJson } from "../../utils/strictJson.js";
import type {
    DirectoryTicketClaims,
    DirectoryTicketVerifier,
    IssueDirectoryTicketOptions,
    LocalDirectoryTicketIssuerOptions,
} from "../types.js";

const textDecoder = new TextDecoder("utf-8", { fatal: true });

interface TicketValue {
    readonly version: 1;
    readonly issuer: string;
    readonly ticketId: string;
    readonly expiresAt: number;
    readonly claimBudget: number;
    readonly signature: string;
}

function signingBytes(value: Omit<TicketValue, "signature">): Uint8Array {
    return canonicalJson({ domain: "murmur.directory.ticket.v1", ...value });
}

function parseTicket(ticket: Uint8Array): TicketValue {
    let parsed: unknown;
    try {
        parsed = parseStrictJson(textDecoder.decode(ticket));
    } catch {
        throw new Error("Invalid directory claim ticket");
    }
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("Invalid directory claim ticket");
    }
    const value = parsed as Record<string, unknown>;
    const fields = ["version", "issuer", "ticketId", "expiresAt", "claimBudget", "signature"];
    if (
        value.version !== 1 ||
        typeof value.issuer !== "string" ||
        value.issuer.length < 1 ||
        value.issuer.length > 128 ||
        typeof value.ticketId !== "string" ||
        typeof value.signature !== "string" ||
        typeof value.expiresAt !== "number" ||
        !Number.isSafeInteger(value.expiresAt) ||
        value.expiresAt < 0 ||
        typeof value.claimBudget !== "number" ||
        !Number.isSafeInteger(value.claimBudget) ||
        value.claimBudget < 1 ||
        value.claimBudget > 1_000_000 ||
        Object.keys(value).some((field) => !fields.includes(field))
    ) {
        throw new Error("Invalid directory claim ticket");
    }
    decodeBase64Url(value.ticketId, 32);
    decodeBase64Url(value.signature, 64);
    return value as unknown as TicketValue;
}

/** Small Ed25519 ticket authority for local deployments and real-store tests. */
export class LocalDirectoryTicketIssuer implements DirectoryTicketVerifier {
    readonly #issuer: string;
    readonly #secretKey: Uint8Array;
    readonly #publicKey: Uint8Array;

    constructor(options: LocalDirectoryTicketIssuerOptions = {}) {
        this.#issuer = options.issuer ?? "murmur-local-directory";
        if (this.#issuer.length < 1 || this.#issuer.length > 128) {
            throw new Error("Directory ticket issuer must contain 1 through 128 characters");
        }
        this.#secretKey = (options.secretKey ?? randomBytes(32)).slice();
        if (this.#secretKey.length !== 32) throw new Error("Invalid ticket issuer secret key");
        this.#publicKey = ed25519.getPublicKey(this.#secretKey);
    }

    /** Public verification key for wiring a separate verifier in local tests. */
    get publicKey(): Uint8Array {
        return this.#publicKey.slice();
    }

    /** Issue one opaque, signed ticket with a shared exact-claim budget. */
    issue(options: IssueDirectoryTicketOptions): Uint8Array {
        if (
            !Number.isSafeInteger(options.expiresAt) ||
            options.expiresAt < 0 ||
            !Number.isSafeInteger(options.claimBudget) ||
            options.claimBudget < 1 ||
            options.claimBudget > 1_000_000
        ) {
            throw new Error("Invalid directory ticket policy");
        }
        const ticketId = (options.ticketId ?? randomBytes(32)).slice();
        if (ticketId.length !== 32) throw new Error("Invalid directory ticket ID");
        const unsigned = {
            version: 1 as const,
            issuer: this.#issuer,
            ticketId: encodeBase64Url(ticketId),
            expiresAt: options.expiresAt,
            claimBudget: options.claimBudget,
        };
        return canonicalJson({
            ...unsigned,
            signature: encodeBase64Url(ed25519.sign(signingBytes(unsigned), this.#secretKey)),
        });
    }

    /** Verify a local/test ticket exactly as a pluggable authentication server would. */
    verify(ticket: Uint8Array, now: number): DirectoryTicketClaims {
        if (!Number.isSafeInteger(now) || now < 0) throw new Error("Invalid directory clock");
        const parsed = parseTicket(ticket);
        const { signature, ...unsigned } = parsed;
        if (
            parsed.issuer !== this.#issuer ||
            !ed25519.verify(
                decodeBase64Url(signature, 64),
                signingBytes(unsigned),
                this.#publicKey,
                { zip215: false },
            )
        ) {
            throw new Error("Invalid directory claim ticket signature");
        }
        return {
            issuer: parsed.issuer,
            ticketId: decodeBase64Url(parsed.ticketId, 32),
            expiresAt: parsed.expiresAt,
            claimBudget: parsed.claimBudget,
        };
    }
}
