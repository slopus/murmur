import { RelayConflictError, RelayError, type SignedRelayEvent } from "../../protocol/index.js";

/** Existing list version loaded under the backend's topic write lock. */
export interface ExistingElement {
    readonly version: bigint;
}

/** Planned list action with its relay-assigned resulting version and position. */
export type PlannedListAction =
    | {
          readonly op: "append";
          readonly id: string;
          readonly version: bigint;
          readonly position: bigint;
          readonly bytes: Uint8Array;
      }
    | {
          readonly op: "replace";
          readonly id: string;
          readonly version: bigint;
          readonly bytes: Uint8Array;
      }
    | {
          readonly op: "delete";
          readonly id: string;
      };

/** Complete mutation plan which a backend applies only after all checks pass. */
export interface EventMutationPlan {
    readonly snapshotVersion: bigint | undefined;
    readonly listActions: readonly PlannedListAction[];
    readonly nextPosition: bigint;
    readonly elementCount: bigint;
}

/** Simulate snapshot and list mutations using versions read inside one write transaction. */
export function planEventMutations(
    event: SignedRelayEvent,
    currentSnapshotVersion: bigint | undefined,
    snapshotGeneration: bigint,
    existingElements: ReadonlyMap<string, ExistingElement>,
    initialElementCount: bigint,
    initialNextPosition: bigint,
    maximumElementsPerTopic: number,
): EventMutationPlan {
    const reportedElements: Record<string, bigint> = {};
    for (const operation of event.list ?? []) {
        reportedElements[operation.id] = existingElements.get(operation.id)?.version ?? 0n;
    }

    let conflict = false;
    let nextSnapshotVersion: bigint | undefined;
    if (event.snapshot !== undefined) {
        const expectedVersion = BigInt(event.snapshot.expectedVersion);
        const matches =
            expectedVersion === 0n
                ? currentSnapshotVersion === undefined
                : currentSnapshotVersion === expectedVersion;
        if (!matches) {
            conflict = true;
        } else {
            nextSnapshotVersion = snapshotGeneration + 1n;
        }
    }

    const simulated = new Map(existingElements);
    const actions: PlannedListAction[] = [];
    let elementCount = initialElementCount;
    let nextPosition = initialNextPosition;
    for (const operation of event.list ?? []) {
        const current = simulated.get(operation.id);
        if (operation.op === "append") {
            if (current !== undefined) {
                conflict = true;
                continue;
            }
            nextPosition += 1n;
            elementCount += 1n;
            simulated.set(operation.id, { version: 1n });
            actions.push({
                op: "append",
                id: operation.id,
                version: 1n,
                position: nextPosition,
                bytes: operation.bytes,
            });
            continue;
        }
        if (
            current === undefined ||
            (operation.expectedVersion !== undefined &&
                BigInt(operation.expectedVersion) !== current.version)
        ) {
            conflict = true;
            continue;
        }
        if (operation.op === "replace") {
            const version = current.version + 1n;
            simulated.set(operation.id, { version });
            actions.push({
                op: "replace",
                id: operation.id,
                version,
                bytes: operation.bytes,
            });
        } else {
            simulated.delete(operation.id);
            elementCount -= 1n;
            actions.push({ op: "delete", id: operation.id });
        }
    }

    if (conflict) {
        throw new RelayConflictError(snapshotGeneration, reportedElements);
    }
    if (elementCount > BigInt(maximumElementsPerTopic)) {
        throw new RelayError(413, "Topic list element limit exceeded", {
            error: "limit",
        });
    }
    return {
        snapshotVersion: nextSnapshotVersion,
        listActions: actions,
        nextPosition,
        elementCount,
    };
}
