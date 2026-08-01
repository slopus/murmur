import { isIP } from "node:net";

/** Explicit policy under which proxy-provided client addresses may be trusted. */
export type TrustedProxyPolicy = number | readonly string[];

function normalizeIp(value: string): string | undefined {
    const trimmed = value.trim();
    const unwrapped =
        trimmed.startsWith("[") && trimmed.endsWith("]") ? trimmed.slice(1, -1) : trimmed;
    const normalized =
        unwrapped.toLowerCase().startsWith("::ffff:") && isIP(unwrapped.slice(7)) === 4
            ? unwrapped.slice(7)
            : unwrapped;
    return isIP(normalized) === 0 ? undefined : normalized.toLowerCase();
}

function forwardedAddresses(request: Request): readonly string[] | undefined {
    const header = request.headers.get("x-forwarded-for");
    if (header === null) {
        return [];
    }
    const values = header.split(",");
    if (values.length > 100) {
        return undefined;
    }
    const normalized: string[] = [];
    for (const value of values) {
        const address = normalizeIp(value);
        if (address === undefined) {
            return undefined;
        }
        normalized.push(address);
    }
    return normalized;
}

/**
 * Resolve the rate-limit address without trusting caller-controlled forwarding
 * headers unless an explicit trusted-proxy policy permits it.
 */
export function resolveClientIp(
    request: Request,
    directAddress: string | undefined,
    trustedProxies: TrustedProxyPolicy | undefined,
): string {
    const direct = directAddress === undefined ? undefined : normalizeIp(directAddress);
    if (direct === undefined) {
        return "unknown";
    }
    if (trustedProxies === undefined) {
        return direct;
    }
    const forwarded = forwardedAddresses(request);
    if (forwarded === undefined || forwarded.length === 0) {
        return direct;
    }
    if (typeof trustedProxies === "number") {
        const index = forwarded.length - trustedProxies;
        return index < 0 ? direct : (forwarded[index] ?? direct);
    }
    const trusted = new Set(
        trustedProxies
            .map((address) => normalizeIp(address))
            .filter((address): address is string => address !== undefined),
    );
    let current = direct;
    for (let index = forwarded.length - 1; index >= 0; index -= 1) {
        if (!trusted.has(current)) {
            return current;
        }
        current = forwarded[index] ?? current;
    }
    return current;
}
