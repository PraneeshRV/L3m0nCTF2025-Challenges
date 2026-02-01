"use client";

import { useState, useRef, useEffect } from "react";
import { harmonizeSpiritThread, runDiagnostics } from "../_actions/recompile";

interface LogEntry {
    id: number;
    type: "input" | "output" | "error" | "system";
    content: string;
    timestamp: Date;
}

export default function CompilerPage() {
    const [input, setInput] = useState("");
    const [logs, setLogs] = useState<LogEntry[]>([
        {
            id: 0,
            type: "system",
            content: "霊圧流動再構成機 (RFR) v2.1.3 initialized.",
            timestamp: new Date(),
        },
        {
            id: 1,
            type: "system",
            content: "Spirit-thread serialization engine online. Awaiting input.",
            timestamp: new Date(),
        },
    ]);
    const [isProcessing, setIsProcessing] = useState(false);
    const logsEndRef = useRef<HTMLDivElement>(null);
    const inputRef = useRef<HTMLInputElement>(null);

    useEffect(() => {
        logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }, [logs]);

    const addLog = (type: LogEntry["type"], content: string) => {
        setLogs((prev) => [
            ...prev,
            { id: Date.now(), type, content, timestamp: new Date() },
        ]);
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!input.trim() || isProcessing) return;

        const fragment = input.trim();
        setInput("");
        setIsProcessing(true);

        addLog("input", `> ${fragment}`);

        try {
            // This triggers the Server Action - vulnerable RSC endpoint
            const result = await harmonizeSpiritThread(fragment);

            if (result.status === "forbidden") {
                addLog("error", `[禁止] ${result.output}`);
            } else if (result.status === "failed") {
                addLog("error", `[失敗] ${result.output}`);
            } else {
                addLog("output", result.output);
                addLog(
                    "system",
                    `Resonance: ${(result.resonance * 100).toFixed(1)}% | Fragments: ${result.fragments}`
                );
            }
        } catch (error) {
            addLog("error", `[異常] Spirit-thread harmonization failed unexpectedly.`);
            console.error(error);
        } finally {
            setIsProcessing(false);
            inputRef.current?.focus();
        }
    };

    const handleDiagnostics = async () => {
        setIsProcessing(true);
        addLog("input", "> run_diagnostics()");

        try {
            const diag = await runDiagnostics();
            addLog("system", `Uptime: ${diag.uptime}s | Active Threads: ${diag.threads}`);
            addLog("system", `Core Version: ${diag.version}`);
        } catch {
            addLog("error", "[異常] Diagnostics unavailable.");
        } finally {
            setIsProcessing(false);
        }
    };

    const formatTimestamp = (date: Date) => {
        return date.toLocaleTimeString("ja-JP", {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
        });
    };

    return (
        <div className="max-w-4xl mx-auto px-6 py-12">
            {/* Header */}
            <div className="mb-8">
                <h1 className="text-2xl font-medium text-seireitei-text mb-2">
                    霊圧流動再構成機
                </h1>
                <p className="text-sm text-seireitei-muted">
                    Reiatsu Flow Recompiler — Spirit Thread Reconstruction Terminal
                </p>
            </div>

            {/* Status Bar */}
            <div className="flex items-center gap-6 mb-6 text-xs font-mono">
                <div className="status-active text-green-400/80">Connected</div>
                <span className="text-seireitei-muted">|</span>
                <span className="text-seireitei-muted">Mode: Reconstruction</span>
                <span className="text-seireitei-muted">|</span>
                <button
                    onClick={handleDiagnostics}
                    disabled={isProcessing}
                    className="text-seireitei-accent hover:underline disabled:opacity-50"
                >
                    Run Diagnostics
                </button>
            </div>

            {/* Terminal Window */}
            <div className="terminal-window">
                <div className="terminal-header">
                    <div className="terminal-dot bg-red-500/80" />
                    <div className="terminal-dot bg-yellow-500/80" />
                    <div className="terminal-dot bg-green-500/80" />
                    <span className="ml-4 text-xs text-seireitei-muted font-mono">
                        rfr-terminal — spirit-thread@seireitei
                    </span>
                </div>

                {/* Logs Display */}
                <div className="h-96 overflow-y-auto p-4 font-mono text-sm">
                    {logs.map((log) => (
                        <div
                            key={log.id}
                            className={`mb-2 ${log.type === "input"
                                    ? "text-seireitei-accent"
                                    : log.type === "error"
                                        ? "text-red-400"
                                        : log.type === "system"
                                            ? "text-seireitei-muted"
                                            : "text-seireitei-text"
                                }`}
                        >
                            <span className="text-seireitei-muted/50 mr-2">
                                [{formatTimestamp(log.timestamp)}]
                            </span>
                            {log.content}
                        </div>
                    ))}
                    {isProcessing && (
                        <div className="text-seireitei-muted animate-pulse">
                            Processing spirit-thread...
                        </div>
                    )}
                    <div ref={logsEndRef} />
                </div>

                {/* Input Area */}
                <form onSubmit={handleSubmit} className="border-t border-seireitei-purple/20 p-4">
                    <div className="flex items-center gap-2">
                        <span className="text-seireitei-accent font-mono">❯</span>
                        <input
                            ref={inputRef}
                            type="text"
                            value={input}
                            onChange={(e) => setInput(e.target.value)}
                            placeholder="Enter spirit-thread fragment..."
                            disabled={isProcessing}
                            className="terminal-input"
                            autoFocus
                        />
                        <button
                            type="submit"
                            disabled={isProcessing || !input.trim()}
                            className="btn-seireitei text-xs py-2 px-4 disabled:opacity-50"
                        >
                            Harmonize
                        </button>
                    </div>
                </form>
            </div>

            {/* Usage Hints */}
            <div className="mt-8 p-4 bg-seireitei-purple/10 border border-seireitei-purple/20 rounded-lg">
                <h3 className="text-sm font-medium text-seireitei-accent mb-2">
                    使用方法 — Usage
                </h3>
                <ul className="text-xs text-seireitei-muted space-y-1">
                    <li>• Enter scroll fragments for reconstruction analysis</li>
                    <li>• Resonance patterns are automatically harmonized</li>
                    <li>• Forbidden patterns will trigger Central 46 protocols</li>
                    <li>• Run diagnostics to check system status</li>
                </ul>
            </div>

            {/* Hidden: Protocol documentation reference */}
            {/* Spirit-thread protocol based on Flight serialization. See internal docs for chunk structure. */}
        </div>
    );
}
