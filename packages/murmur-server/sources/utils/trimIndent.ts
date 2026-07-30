export function trimIdent(str: string): string {
    const lines = str.split("\n");

    // Remove leading/trailing empty lines
    while (lines.length > 0 && lines[0].trim() === "") {
        lines.shift();
    }
    while (lines.length > 0 && lines[lines.length - 1].trim() === "") {
        lines.pop();
    }

    if (lines.length === 0) {
        return "";
    }

    // Find minimum indentation
    const minIndent = lines
        .filter((line) => line.trim() !== "")
        .reduce((min, line) => {
            const indent = line.match(/^(\s*)/)?.[1].length || 0;
            return Math.min(min, indent);
        }, Infinity);

    // Remove common indentation
    return lines.map((line) => line.slice(minIndent)).join("\n");
}
