"use client";

import { useState } from "react";

export default function AuthPage() {
    const [soulSignature, setSoulSignature] = useState("");
    const [barrierCode, setBarrierCode] = useState("");
    const [error, setError] = useState("");
    const [isVerifying, setIsVerifying] = useState(false);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setIsVerifying(true);
        setError("");

        // Simulate verification delay
        await new Promise((r) => setTimeout(r, 1500));

        // This is a red herring - no actual auth vulnerability here
        // All validation is client-side theater
        if (!soulSignature || !barrierCode) {
            setError("Incomplete spiritual signature detected.");
        } else if (barrierCode.length < 8) {
            setError("Barrier code insufficient. Minimum 8 characters required.");
        } else {
            setError("Authentication failed. Spiritual signature not recognized by Central 46 registry.");
        }

        setIsVerifying(false);
    };

    return (
        <div className="max-w-md mx-auto px-6 py-12">
            {/* Header */}
            <div className="text-center mb-12">
                <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-seireitei-purple/30 border border-seireitei-glow/30 mb-4">
                    <span className="text-2xl">結界</span>
                </div>
                <h1 className="text-xl font-medium text-seireitei-text mb-2">
                    Barrier Authentication
                </h1>
                <p className="text-sm text-seireitei-muted">
                    Kidō Corps Security Protocol 73
                </p>
            </div>

            {/* Auth Form */}
            <div className="terminal-window p-6">
                <form onSubmit={handleSubmit} className="space-y-6">
                    <div>
                        <label className="block text-sm text-seireitei-muted mb-2">
                            Soul Signature (霊圧署名)
                        </label>
                        <input
                            type="text"
                            value={soulSignature}
                            onChange={(e) => setSoulSignature(e.target.value)}
                            placeholder="Enter your spiritual identifier..."
                            className="w-full bg-seireitei-deeper border border-seireitei-purple/30 rounded px-4 py-3 text-sm text-seireitei-text placeholder-seireitei-muted/50 focus:outline-none focus:border-seireitei-glow transition-colors font-mono"
                        />
                    </div>

                    <div>
                        <label className="block text-sm text-seireitei-muted mb-2">
                            Barrier Code (障壁暗号)
                        </label>
                        <input
                            type="password"
                            value={barrierCode}
                            onChange={(e) => setBarrierCode(e.target.value)}
                            placeholder="••••••••"
                            className="w-full bg-seireitei-deeper border border-seireitei-purple/30 rounded px-4 py-3 text-sm text-seireitei-text placeholder-seireitei-muted/50 focus:outline-none focus:border-seireitei-glow transition-colors font-mono"
                        />
                    </div>

                    {error && (
                        <div className="p-3 bg-red-900/20 border border-red-800/30 rounded text-sm text-red-400">
                            {error}
                        </div>
                    )}

                    <button
                        type="submit"
                        disabled={isVerifying}
                        className="w-full btn-seireitei disabled:opacity-50"
                    >
                        {isVerifying ? "Verifying..." : "Authenticate"}
                    </button>
                </form>

                <div className="mt-6 pt-6 border-t border-seireitei-purple/20">
                    <p className="text-xs text-seireitei-muted text-center">
                        Authentication managed by Central 46 Spiritual Registry.
                        <br />
                        Unauthorized access attempts are logged and reported.
                    </p>
                </div>
            </div>

            {/* Fake Security Notice */}
            <div className="mt-8 p-4 bg-yellow-900/10 border border-yellow-700/20 rounded-lg">
                <div className="flex items-start gap-3">
                    <span className="text-yellow-500/80">⚠</span>
                    <div className="text-xs text-seireitei-muted">
                        <strong className="text-yellow-500/80">Security Notice:</strong> This endpoint is protected by
                        Kidō Barrier Class 73 (倒山晶). All authentication attempts are monitored
                        by the Onmitsukidō Intelligence Division.
                    </div>
                </div>
            </div>
        </div>
    );
}
