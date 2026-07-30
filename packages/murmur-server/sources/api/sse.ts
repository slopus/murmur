import type { FastifyReply } from "fastify";

/**
 * SSE (Server-Sent Events) connection manager
 */
export class SSEConnection {
    private reply: FastifyReply;
    private closed = false;

    constructor(reply: FastifyReply) {
        this.reply = reply;

        // Set SSE headers
        reply.raw.writeHead(200, {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            Connection: "keep-alive",
        });

        // Handle client disconnect
        reply.raw.on("close", () => {
            this.closed = true;
        });
    }

    /**
     * Send an event to the client
     */
    send(event: string, data: any): void {
        if (this.closed) {
            return;
        }

        const payload = JSON.stringify(data);
        this.reply.raw.write(`event: ${event}\n`);
        this.reply.raw.write(`data: ${payload}\n\n`);
    }

    /**
     * Send a heartbeat to keep connection alive
     */
    heartbeat(): void {
        if (this.closed) {
            return;
        }

        this.reply.raw.write(": heartbeat\n\n");
    }

    /**
     * Check if connection is still open
     */
    isOpen(): boolean {
        return !this.closed;
    }

    /**
     * Close the connection
     */
    close(): void {
        if (!this.closed) {
            this.reply.raw.end();
            this.closed = true;
        }
    }
}

/**
 * Manage multiple SSE connections for a user
 */
export class SSEConnectionManager {
    private connections = new Map<string, Set<SSEConnection>>();

    /**
     * Add a new connection for a user
     */
    addConnection(userId: string, connection: SSEConnection): void {
        if (!this.connections.has(userId)) {
            this.connections.set(userId, new Set());
        }

        this.connections.get(userId)!.add(connection);

        // Remove connection when it closes
        const checkClosed = () => {
            if (!connection.isOpen()) {
                this.removeConnection(userId, connection);
            }
        };

        // Check periodically if connection is still open
        const interval = setInterval(checkClosed, 5000);

        // Clean up interval when connection closes
        const originalClose = connection.close.bind(connection);
        connection.close = () => {
            clearInterval(interval);
            originalClose();
        };
    }

    /**
     * Remove a connection
     */
    removeConnection(userId: string, connection: SSEConnection): void {
        const userConnections = this.connections.get(userId);
        if (userConnections) {
            userConnections.delete(connection);
            if (userConnections.size === 0) {
                this.connections.delete(userId);
            }
        }
    }

    /**
     * Send an event to all connections for a user
     */
    sendToUser(userId: string, event: string, data: any): void {
        const userConnections = this.connections.get(userId);
        if (!userConnections) {
            return;
        }

        for (const connection of userConnections) {
            if (connection.isOpen()) {
                connection.send(event, data);
            } else {
                this.removeConnection(userId, connection);
            }
        }
    }

    /**
     * Get number of active connections for a user
     */
    getConnectionCount(userId: string): number {
        return this.connections.get(userId)?.size || 0;
    }
}

export const sseManager = new SSEConnectionManager();
