import { DEFAULT_RELAY_URL } from "@slopus/murmur";

/** Collect every occurrence of one long bootstrap option. */
export function repeatedOption(arguments_: readonly string[], name: string): readonly string[] {
    const values: string[] = [];
    for (let index = 0; index < arguments_.length; index += 1) {
        const argument = arguments_[index];
        if (argument === `--${name}`) {
            const value = arguments_[index + 1];
            if (value === undefined || value.startsWith("-")) {
                throw new Error(`Missing --${name} value`);
            }
            values.push(value);
            index += 1;
        } else if (argument?.startsWith(`--${name}=`)) {
            values.push(argument.slice(name.length + 3));
        }
    }
    return values;
}

/** Resolve CLI relay URLs with arguments before environment and the public default last. */
export function relayUrls(
    arguments_: readonly string[],
    environment: string | undefined,
): readonly string[] {
    const configured = repeatedOption(arguments_, "relay");
    if (configured.length > 0) {
        return configured;
    }
    if (environment !== undefined) {
        const values = environment
            .split(",")
            .map((value) => value.trim())
            .filter((value) => value.length > 0);
        if (values.length > 0) {
            return values;
        }
    }
    return [DEFAULT_RELAY_URL];
}
