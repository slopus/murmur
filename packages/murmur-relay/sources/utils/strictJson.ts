/** Syntax error raised when one JSON object repeats a decoded property name. */
export class DuplicateJsonKeyError extends SyntaxError {
    constructor() {
        super("Duplicate JSON object key");
        this.name = "DuplicateJsonKeyError";
    }
}

function whitespace(value: string): boolean {
    return value === " " || value === "\t" || value === "\n" || value === "\r";
}

function stringEnd(input: string, start: number): number {
    let index = start + 1;
    while (index < input.length) {
        if (input[index] === '"') return index;
        if (input[index] === "\\") index += 1;
        index += 1;
    }
    throw new SyntaxError("Unterminated JSON string");
}

function rejectDuplicateObjectKeys(input: string): void {
    const objects: Array<Set<string> | undefined> = [];
    let index = 0;
    while (index < input.length) {
        const token = input[index]!;
        if (token === "{") {
            objects.push(new Set());
            index += 1;
            continue;
        }
        if (token === "[") {
            objects.push(undefined);
            index += 1;
            continue;
        }
        if (token === "}" || token === "]") {
            objects.pop();
            index += 1;
            continue;
        }
        if (token !== '"') {
            index += 1;
            continue;
        }

        const end = stringEnd(input, index);
        let following = end + 1;
        while (following < input.length && whitespace(input[following]!)) following += 1;
        if (input[following] === ":") {
            const objectKeys = objects.at(-1);
            if (objectKeys !== undefined) {
                const decoded = JSON.parse(input.slice(index, end + 1)) as unknown;
                if (typeof decoded !== "string") throw new SyntaxError("Invalid JSON object key");
                if (objectKeys.has(decoded)) throw new DuplicateJsonKeyError();
                objectKeys.add(decoded);
            }
        }
        index = end + 1;
    }
}

/** Parse JSON only when every object has unique decoded property names. */
export function parseStrictJson(input: string): unknown {
    rejectDuplicateObjectKeys(input);
    return JSON.parse(input) as unknown;
}
