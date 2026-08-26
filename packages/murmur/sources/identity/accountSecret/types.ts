/** Application-owned material created when an identity root is wrapped. */
export interface CreatedAccountSecret {
    /** Opaque, versioned encrypted blob which the application persists. */
    readonly blob: string;

    /** High-entropy generated string which must be retained separately from the blob. */
    readonly generatedSecret: string;
}
