import { NextResponse } from "next/server";

// Red herring endpoint - appears to be SSRF-capable but sanitized
// References Aizen and mirror techniques to distract players

interface ArchiveEntry {
    id: string;
    title: string;
    classification: string;
    lastAccessed: string;
    fragments: number;
    notes: string;
}

const archives: ArchiveEntry[] = [
    {
        id: "arc-0001",
        title: "虚圏侵入記録",
        classification: "機密-乙",
        lastAccessed: "1847-03-12",
        fragments: 1203,
        notes: "Hueco Mundo expedition records. Cross-reference with Aizen incident files.",
    },
    {
        id: "arc-0002",
        title: "鏡花水月解析報告",
        classification: "禁書",
        lastAccessed: "REDACTED",
        fragments: 0,
        notes: "Complete hypnosis analysis. ACCESS DENIED - requires Captain-class authorization.",
    },
    {
        id: "arc-0003",
        title: "崩玉創造理論",
        classification: "禁書",
        lastAccessed: "REDACTED",
        fragments: 0,
        notes: "Hōgyoku creation methodology. SEALED by Central 46 Directive.",
    },
    {
        id: "arc-0004",
        title: "斬月・解放限界記録",
        classification: "機密-甲",
        lastAccessed: "2003-10-15",
        fragments: 891,
        notes: "Zangetsu manifestation data. Dual-spirit interference documented.",
    },
];

export async function GET(request: Request) {
    const { searchParams } = new URL(request.url);
    const id = searchParams.get("id");
    const query = searchParams.get("query");

    // Fake URL parameter handling (misdirection for SSRF hunters)
    const _internalRef = searchParams.get("ref");
    if (_internalRef) {
        // Appears to accept URLs but does nothing
        return NextResponse.json(
            { error: "Internal reference protocol not available in external mode." },
            { status: 403 }
        );
    }

    if (id) {
        const entry = archives.find((a) => a.id === id);
        if (!entry) {
            return NextResponse.json({ error: "Archive not found." }, { status: 404 });
        }
        if (entry.classification === "禁書") {
            return NextResponse.json(
                { error: "Access denied. Archive sealed under Central 46 Directive." },
                { status: 403 }
            );
        }
        return NextResponse.json({ archive: entry });
    }

    if (query) {
        const results = archives.filter(
            (a) =>
                a.title.includes(query) ||
                a.notes.toLowerCase().includes(query.toLowerCase())
        );
        return NextResponse.json({ results, total: results.length });
    }

    // Return all non-forbidden archives
    const publicArchives = archives.filter((a) => a.classification !== "禁書");
    return NextResponse.json({
        archives: publicArchives,
        total: publicArchives.length,
        notice: "Forbidden archives require elevated spiritual clearance.",
    });
}
