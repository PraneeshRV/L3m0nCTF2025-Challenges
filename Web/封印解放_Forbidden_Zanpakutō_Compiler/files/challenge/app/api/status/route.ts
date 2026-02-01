import { NextResponse } from "next/server";

// Red herring - appears to be a status/debug endpoint
// Returns fake version information to mislead players

export async function GET() {
    return NextResponse.json({
        status: "operational",
        uptime: Math.floor(process.uptime()),
        version: "14.2.0-Byakuya", // Fake version - misdirection
        build: "stable",
        spiritualIndex: 847,
        activeThreads: 12,
        memoryUsage: {
            heapUsed: Math.floor(process.memoryUsage().heapUsed / 1024 / 1024),
            unit: "MB",
        },
        lastCalibration: "2024-11-28T09:15:00Z",
        notices: [
            "RFR Core operating within normal parameters.",
            "Spirit-thread serialization engine: ONLINE",
            "Barrier authentication: ENABLED",
        ],
    });
}

export async function POST(request: Request) {
    // Appears to accept commands but rejects everything
    const body = await request.json().catch(() => ({}));

    if (body.command) {
        return NextResponse.json(
            {
                error: "Remote command execution disabled.",
                hint: "Administrative commands require physical access to Seireitei terminals.",
            },
            { status: 403 }
        );
    }

    return NextResponse.json({ error: "Invalid request format." }, { status: 400 });
}
