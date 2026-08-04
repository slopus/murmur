import {
    defaultMlsLeafCapabilities,
    encodeMlsLeafNode,
    type MlsLeafNode,
} from "../../leafNode/index.js";
import type { MlsKeyPackageBundle } from "../../keyPackage/index.js";
import type { MlsRatchetTreeLeaf } from "../../ratchetTree/index.js";

/** Convert the creator's KeyPackage leaf into its authenticated tree node. */
export function initialMlsRatchetTreeLeaf(bundle: MlsKeyPackageBundle): MlsRatchetTreeLeaf {
    const keyPackageLeaf = bundle.keyPackage.leafNode;
    const leaf: MlsLeafNode = {
        encryptionKey: keyPackageLeaf.encryptionKey,
        signatureKey: keyPackageLeaf.signatureKey,
        credential: keyPackageLeaf.credential,
        capabilities: defaultMlsLeafCapabilities(),
        source: "key_package",
        notBefore: keyPackageLeaf.notBefore,
        notAfter: keyPackageLeaf.notAfter,
        extensions: [],
        signature: keyPackageLeaf.signature,
    };
    return {
        type: "leaf",
        encoded: encodeMlsLeafNode(leaf),
        encryptionKey: leaf.encryptionKey,
        signatureKey: leaf.signatureKey,
    };
}
