/**
 * Vitest worker setup for the chaos suite.
 *
 * Vitest 3.2.7 waits for a reporter acknowledgement of every task update and
 * times out after sixty seconds. A chaos scenario legitimately runs longer than
 * that, so the acknowledgement expires and the run reports an unhandled error
 * even though every test passed. The event form delivers the same ordered task
 * update without retaining the acknowledgement promise.
 *
 * The chaos configuration loads this file as a setup file so the whole suite
 * shares one correction instead of repeating it in each long-running file.
 */

interface VitestRuntimeRpcMethod {
    (...arguments_: readonly unknown[]): Promise<unknown>;
    readonly asEvent: (...arguments_: readonly unknown[]) => void;
}

interface VitestWorkerState {
    rpc: object;
}

const workerState = (
    globalThis as typeof globalThis & { readonly __vitest_worker__?: VitestWorkerState }
).__vitest_worker__;

if (workerState !== undefined) {
    const delegate = workerState.rpc;
    workerState.rpc = new Proxy(delegate, {
        get(target, property, receiver): unknown {
            const value = Reflect.get(target, property, receiver) as unknown;
            if (property !== "onTaskUpdate" || typeof value !== "function") return value;
            const update = value as VitestRuntimeRpcMethod;
            return (...arguments_: readonly unknown[]): Promise<void> => {
                update.asEvent(...arguments_);
                return Promise.resolve();
            };
        },
    });
}
