import Link from "next/link";

const scrolls = [
    {
        id: "scroll-001",
        title: "斬魄刀基礎構造",
        subtitle: "Zanpakutō Foundational Architecture",
        classification: "機密-丙",
        status: "reconstructed",
        fragments: 847,
    },
    {
        id: "scroll-002",
        title: "虚圏境界理論",
        subtitle: "Hueco Mundo Boundary Theory",
        classification: "機密-乙",
        status: "reconstructed",
        fragments: 1203,
    },
    {
        id: "scroll-003",
        title: "卍解顕現記録",
        subtitle: "Bankai Manifestation Records",
        classification: "機密-甲",
        status: "partial",
        fragments: 2891,
    },
    {
        id: "scroll-004",
        title: "禁術・封印解放",
        subtitle: "Forbidden Technique: Seal Release",
        classification: "禁書",
        status: "corrupted",
        fragments: 0,
    },
];

export default function HomePage() {
    return (
        <div className="max-w-6xl mx-auto px-6 py-12">
            {/* Header */}
            <div className="text-center mb-16">
                <h1 className="kanji-title mb-4">鳳凰殿</h1>
                <p className="text-xl text-seireitei-muted mb-2">Hōōden Sealed Archive</p>
                <p className="text-sm text-seireitei-muted/60 max-w-xl mx-auto">
                    霊子再構成システム — Kidō Corps Document Restoration Initiative
                </p>
            </div>

            {/* Status Banner */}
            <div className="terminal-window mb-12 p-4">
                <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                        <div className="status-active text-sm text-green-400/80">
                            System Online
                        </div>
                        <span className="text-seireitei-muted text-sm">|</span>
                        <span className="text-sm text-seireitei-muted font-mono">
                            Active Threads: 12
                        </span>
                    </div>
                    <span className="text-xs text-seireitei-muted font-mono">
                        Session: 0x7F3A...E91C
                    </span>
                </div>
            </div>

            {/* Scrolls Grid */}
            <div className="mb-12">
                <h2 className="text-lg font-medium mb-6 flex items-center gap-2">
                    <span className="text-seireitei-accent">巻物索引</span>
                    <span className="text-seireitei-muted">— Scroll Index</span>
                </h2>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {scrolls.map((scroll) => (
                        <div key={scroll.id} className="scroll-card">
                            <div className="flex items-start justify-between mb-3">
                                <div>
                                    <h3 className="text-seireitei-text font-medium">{scroll.title}</h3>
                                    <p className="text-xs text-seireitei-muted">{scroll.subtitle}</p>
                                </div>
                                <span className={`text-xs px-2 py-1 rounded font-mono ${scroll.classification === "禁書"
                                        ? "bg-red-900/30 text-red-400 border border-red-800/50"
                                        : "bg-seireitei-purple/30 text-seireitei-accent"
                                    }`}>
                                    {scroll.classification}
                                </span>
                            </div>

                            <div className="flex items-center justify-between text-xs">
                                <span className={`${scroll.status === "reconstructed" ? "text-green-400/80" :
                                        scroll.status === "partial" ? "text-yellow-400/80" :
                                            "text-red-400/80"
                                    }`}>
                                    {scroll.status === "reconstructed" ? "● Reconstructed" :
                                        scroll.status === "partial" ? "◐ Partial Recovery" :
                                            "○ Corrupted"}
                                </span>
                                <span className="text-seireitei-muted font-mono">
                                    {scroll.fragments > 0 ? `${scroll.fragments} fragments` : "—"}
                                </span>
                            </div>
                        </div>
                    ))}
                </div>
            </div>

            {/* Action Section */}
            <div className="terminal-window p-6">
                <div className="flex items-center gap-3 mb-4">
                    <div className="w-2 h-2 rounded-full bg-seireitei-accent animate-pulse" />
                    <span className="text-sm text-seireitei-muted font-mono">
                        霊圧流動再構成機 (RFR) Ready
                    </span>
                </div>

                <p className="text-seireitei-muted text-sm mb-6">
                    The Reiatsu Flow Recompiler can attempt reconstruction of corrupted spirit-thread archives.
                    Access requires authorized spiritual signature verification.
                </p>

                <div className="flex gap-4">
                    <Link href="/compiler" className="btn-seireitei">
                        Access Recompiler →
                    </Link>
                    <Link href="/auth" className="btn-seireitei opacity-60">
                        Barrier Authentication
                    </Link>
                </div>
            </div>

            {/* Hidden comment for curious players */}
            {/* DEBUG: RFR-Core v2.1.3 - Spirit thread serialization adapted from Urahara's prototype */}
            {/* WARNING: Do not pass unverified resonance patterns to harmonizeSpiritThread() */}
        </div>
    );
}
