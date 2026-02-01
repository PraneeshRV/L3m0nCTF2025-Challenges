"use strict";
// memory.ts - Shared Memory with Session TTL
Object.defineProperty(exports, "__esModule", { value: true });
exports.globalMemory = exports.SharedMemory = void 0;
class SharedMemory {
    constructor() {
        this.store = new Map();
        this.MAX_ENTRIES_PER_USER = 10;
        this.TTL_MS = 30 * 60 * 1000; // 30 minutes
    }
    addLog(userId, content) {
        this.cleanup(); // Clear expired entries periodically
        const logs = this.store.get(userId) || [];
        logs.push({ userId, summary: content, timestamp: Date.now() });
        // Limit entries per user to prevent memory bloat
        if (logs.length > this.MAX_ENTRIES_PER_USER) {
            logs.shift();
        }
        this.store.set(userId, logs);
    }
    getLatestLog(userId) {
        const logs = this.store.get(userId);
        if (!logs || logs.length === 0)
            return "No history found.";
        return logs[logs.length - 1].summary;
    }
    // Get all logs for a user (for memory visualization)
    getAllLogs(userId) {
        return this.store.get(userId) || [];
    }
    // Clean up expired entries to prevent memory leaks
    cleanup() {
        const now = Date.now();
        this.store.forEach((logs, userId) => {
            const validLogs = logs.filter(log => now - log.timestamp < this.TTL_MS);
            if (validLogs.length === 0) {
                this.store.delete(userId);
            }
            else {
                this.store.set(userId, validLogs);
            }
        });
    }
    // Get store size for monitoring
    getStats() {
        let entries = 0;
        this.store.forEach(logs => entries += logs.length);
        return { users: this.store.size, entries };
    }
}
exports.SharedMemory = SharedMemory;
exports.globalMemory = new SharedMemory();
