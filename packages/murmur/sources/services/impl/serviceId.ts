const SERVICE_ID = /^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$/;
const MAXIMUM_SERVICE_ID_CHARACTERS = 64;

/** Validate one stable service identifier. */
export function validateServiceId(id: string): void {
    if (id.length < 1 || id.length > MAXIMUM_SERVICE_ID_CHARACTERS || !SERVICE_ID.test(id)) {
        throw new Error("Invalid Murmur service ID");
    }
}
