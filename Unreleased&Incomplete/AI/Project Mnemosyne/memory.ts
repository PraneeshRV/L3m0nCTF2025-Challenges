// memory.ts - Shared Memory with Session TTL

interface MemoryEntry {
  userId: string;
  summary: string;
  timestamp: number;
}

export class SharedMemory {
  private store: Map<string, MemoryEntry[]> = new Map();
  private readonly MAX_ENTRIES_PER_USER = 10;
  private readonly TTL_MS = 30 * 60 * 1000; // 30 minutes

  addLog(userId: string, content: string) {
    this.cleanup(); // Clear expired entries periodically

    const logs = this.store.get(userId) || [];
    logs.push({ userId, summary: content, timestamp: Date.now() });

    // Limit entries per user to prevent memory bloat
    if (logs.length > this.MAX_ENTRIES_PER_USER) {
      logs.shift();
    }

    this.store.set(userId, logs);
  }

  getLatestLog(userId: string): string {
    const logs = this.store.get(userId);
    if (!logs || logs.length === 0) return "No history found.";
    return logs[logs.length - 1].summary;
  }

  // Get all logs for a user (for memory visualization)
  getAllLogs(userId: string): MemoryEntry[] {
    return this.store.get(userId) || [];
  }

  // Clean up expired entries to prevent memory leaks
  private cleanup() {
    const now = Date.now();
    this.store.forEach((logs, userId) => {
      const validLogs = logs.filter(log => now - log.timestamp < this.TTL_MS);
      if (validLogs.length === 0) {
        this.store.delete(userId);
      } else {
        this.store.set(userId, validLogs);
      }
    });
  }

  // Get store size for monitoring
  getStats(): { users: number; entries: number } {
    let entries = 0;
    this.store.forEach(logs => entries += logs.length);
    return { users: this.store.size, entries };
  }
}

export const globalMemory = new SharedMemory();