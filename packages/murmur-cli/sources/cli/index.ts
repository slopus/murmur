import { readFile, stat, writeFile } from "node:fs/promises";
import { basename } from "node:path";
import { identityId } from "@murmur/core";
import {
    MAX_CLI_ATTACHMENTS,
    MAX_CLI_ATTACHMENT_BYTES,
    encodeCliIdentityToken,
    type MurmurCliRuntime,
} from "../runtime/index.js";

interface ParsedArguments {
    readonly command?: string;
    readonly positionals: readonly string[];
    readonly options: ReadonlyMap<string, readonly string[]>;
    readonly flags: ReadonlySet<string>;
}

function parseArguments(arguments_: readonly string[]): ParsedArguments {
    let command: string | undefined;
    const positionals: string[] = [];
    const options = new Map<string, string[]>();
    const flags = new Set<string>();
    for (let index = 0; index < arguments_.length; index += 1) {
        const argument = arguments_[index];
        if (argument === undefined) {
            continue;
        }
        if (argument === "-h" || argument === "--help") {
            flags.add("help");
            continue;
        }
        if (argument === "-n") {
            const value = arguments_[index + 1];
            if (value === undefined) {
                throw new Error("Missing value after -n");
            }
            options.set("limit", [value]);
            index += 1;
            continue;
        }
        if (argument.startsWith("--")) {
            const separator = argument.indexOf("=");
            const name = separator === -1 ? argument.slice(2) : argument.slice(2, separator);
            const inlineValue = separator === -1 ? undefined : argument.slice(separator + 1);
            const next = inlineValue ?? arguments_[index + 1];
            if (inlineValue === undefined && (next === undefined || next.startsWith("-"))) {
                flags.add(name);
                continue;
            }
            if (inlineValue === undefined) {
                index += 1;
            }
            const values = options.get(name) ?? [];
            values.push(next ?? "");
            options.set(name, values);
            continue;
        }
        if (command === undefined) {
            command = argument;
        } else {
            positionals.push(argument);
        }
    }
    return {
        ...(command === undefined ? {} : { command }),
        positionals,
        options,
        flags,
    };
}

function option(
    parsed: ParsedArguments,
    name: string,
    required: boolean = false,
): string | undefined {
    const value = parsed.options.get(name)?.[0];
    if (required && (value === undefined || value.length === 0)) {
        throw new Error(`Missing --${name}`);
    }
    return value;
}

function positiveInteger(value: string | undefined, fallback: number): number {
    if (value === undefined) {
        return fallback;
    }
    const parsed = Number(value);
    if (!Number.isSafeInteger(parsed) || parsed < 1) {
        throw new Error(`Invalid positive integer: ${value}`);
    }
    return parsed;
}

function help(): string {
    return [
        "Usage:",
        "  murmur sign-in --first-name <name> [--last-name <name>]",
        "  murmur me",
        "  murmur contacts",
        "  murmur contacts add <identity-token>",
        "  murmur contacts remove <identity-id-or-token>",
        "  murmur send --to <identity-id-or-token> --message <text> [--attach <path> ...]",
        "  murmur sync [--realtime] [--timeout <milliseconds>]",
        "  murmur messages [--with <identity-id-or-token>] [--limit <count>]",
        "  murmur attachment --message <id> --name <file> --out <path>",
        "",
        "Global: --relay <url> (repeatable), --db <sqlite-path>",
    ].join("\n");
}

/** Execute one parsed command against an already opened runtime. */
export async function runCli(
    runtime: MurmurCliRuntime,
    arguments_: readonly string[],
    write: (text: string) => void = (text) => process.stdout.write(text),
): Promise<void> {
    const parsed = parseArguments(arguments_);
    if (parsed.command === undefined || parsed.command === "help" || parsed.flags.has("help")) {
        write(`${help()}\n`);
        return;
    }

    switch (parsed.command) {
        case "sign-in": {
            const firstName = option(parsed, "first-name") ?? option(parsed, "name", true);
            const lastName = option(parsed, "last-name");
            const name = [firstName, lastName].filter((part) => part !== undefined).join(" ");
            const identity = await runtime.signIn({ name });
            write(
                `${JSON.stringify({
                    id: identity.id,
                    token: identity.token,
                    name: identity.profile.name,
                })}\n`,
            );
            return;
        }
        case "me": {
            const identity = runtime.publicIdentity();
            write(
                `${JSON.stringify({
                    id: identity.id,
                    token: identity.token,
                    name: identity.profile.name,
                })}\n`,
            );
            return;
        }
        case "contacts": {
            const action = parsed.positionals[0];
            if (action === "add") {
                const token = parsed.positionals[1];
                if (token === undefined) {
                    throw new Error("Usage: murmur contacts add <identity-token>");
                }
                await runtime.shareProfile(token);
                write(`${JSON.stringify({ status: "profile-sent" })}\n`);
                return;
            }
            if (action === "remove") {
                const identity = parsed.positionals[1];
                if (identity === undefined) {
                    throw new Error("Usage: murmur contacts remove <identity-id-or-token>");
                }
                await runtime.removeContact(identity);
                write(`${JSON.stringify({ status: "removed" })}\n`);
                return;
            }
            if (action !== undefined) {
                throw new Error(`Unknown contacts action: ${action}`);
            }
            const contacts = await runtime.contacts();
            write(
                `${JSON.stringify(
                    contacts.map((contact) => ({
                        id: identityId(contact.identity),
                        token: encodeCliIdentityToken(contact.identity),
                        name: contact.profile.name,
                        addedAt: contact.addedAt,
                        updatedAt: contact.updatedAt,
                    })),
                )}\n`,
            );
            return;
        }
        case "send": {
            const recipient = option(parsed, "to", true) ?? "";
            const message = option(parsed, "message", true) ?? "";
            const attachments: { name: string; bytes: Uint8Array }[] = [];
            try {
                const paths = parsed.options.get("attach") ?? [];
                if (paths.length > MAX_CLI_ATTACHMENTS) {
                    throw new Error(
                        `A CLI message may contain at most ${MAX_CLI_ATTACHMENTS} attachments`,
                    );
                }
                let total = 0;
                for (const path of paths) {
                    const statistics = await stat(path);
                    if (!statistics.isFile()) {
                        throw new Error(`Attachment is not a regular file: ${path}`);
                    }
                    total += statistics.size;
                    if (!Number.isSafeInteger(total) || total > MAX_CLI_ATTACHMENT_BYTES) {
                        throw new Error(
                            `CLI message attachments exceed ${MAX_CLI_ATTACHMENT_BYTES} aggregate bytes`,
                        );
                    }
                    const bytes = new Uint8Array(await readFile(path));
                    const actualTotal =
                        attachments.reduce((sum, attachment) => sum + attachment.bytes.length, 0) +
                        bytes.length;
                    if (actualTotal > MAX_CLI_ATTACHMENT_BYTES) {
                        bytes.fill(0);
                        throw new Error(
                            `CLI message attachments exceed ${MAX_CLI_ATTACHMENT_BYTES} aggregate bytes`,
                        );
                    }
                    attachments.push({
                        name: basename(path),
                        bytes,
                    });
                }
                const messageId = await runtime.send(recipient, message, attachments);
                write(`${JSON.stringify({ id: messageId, status: "sent" })}\n`);
            } finally {
                for (const attachment of attachments) {
                    attachment.bytes.fill(0);
                }
            }
            return;
        }
        case "sync": {
            const timeout = positiveInteger(
                option(parsed, "timeout"),
                parsed.flags.has("realtime") ? 25_000 : 1,
            );
            const result = await runtime.sync(parsed.flags.has("realtime") ? timeout : 0);
            write(`${JSON.stringify(result)}\n`);
            return;
        }
        case "messages": {
            const messages = await runtime.messages(
                option(parsed, "with"),
                positiveInteger(option(parsed, "limit"), 100),
            );
            try {
                write(
                    `${JSON.stringify(
                        messages.map((stored) => ({
                            id: stored.message.id,
                            conversationId: stored.conversationId,
                            direction: stored.direction,
                            status: stored.status,
                            sentAt: stored.message.sentAt,
                            text: stored.message.text,
                            attachments: stored.message.attachments.map((attachment) => ({
                                name: attachment.name,
                                mediaType: attachment.mediaType,
                                plaintextBytes: attachment.plaintextBytes,
                            })),
                        })),
                    )}\n`,
                );
            } finally {
                for (const stored of messages) {
                    for (const attachment of stored.message.attachments) {
                        attachment.key.fill(0);
                        attachment.nonce.fill(0);
                    }
                }
            }
            return;
        }
        case "attachment": {
            const messageId = option(parsed, "message", true) ?? "";
            const name = option(parsed, "name", true) ?? "";
            const output = option(parsed, "out", true) ?? "";
            const plaintext = await runtime.attachment(messageId, name);
            try {
                await writeFile(output, plaintext, { flag: "wx" });
            } finally {
                plaintext.fill(0);
            }
            write(`${JSON.stringify({ messageId, name, output })}\n`);
            return;
        }
        default:
            throw new Error(`Unknown command: ${parsed.command}`);
    }
}
