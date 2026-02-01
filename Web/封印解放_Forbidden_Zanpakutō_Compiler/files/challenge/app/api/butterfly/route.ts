import { NextResponse } from "next/server";

// Red herring - appears to be SSRF-vulnerable but isn't

export async function POST(request: Request) {
    const body = await request.json().catch(() => ({}));

    // Looks like it accepts URLs (SSRF bait)
    if (body.destination) {
        // Appears to validate URLs...
        const urlPattern = /^https?:\/\/.+/;
        if (!urlPattern.test(body.destination)) {
            return NextResponse.json(
                { error: "Invalid jigokuchō destination format." },
                { status: 400 }
            );
        }

        // But actually just rejects everything
        return NextResponse.json(
            {
                error: "External destinations blocked by Senkaimon security protocol.",
                code: "BARRIER_ACTIVE",
                hint: "Only intra-Seireitei communications are permitted.",
            },
            { status: 403 }
        );
    }

    if (body.target) {
        // Another bait - looks like internal routing
        const allowedTargets = ["division-4", "division-12", "kido-corps"];
        if (!allowedTargets.includes(body.target)) {
            return NextResponse.json(
                { error: `Target '${body.target}' not in authorized routing table.` },
                { status: 403 }
            );
        }

        return NextResponse.json({
            status: "queued",
            target: body.target,
            estimatedDelivery: "2-4 spiritual cycles",
            messageId: `jgk-${Date.now().toString(36)}`,
        });
    }

    return NextResponse.json(
        {
            error: "Missing required field: 'destination' or 'target'",
            usage: {
                destination: "External URL (currently disabled)",
                target: "Internal division identifier",
            },
        },
        { status: 400 }
    );
}

export async function GET() {
    return NextResponse.json({
        service: "Hell Butterfly Messaging System",
        version: "3.1.0",
        status: "active",
        note: "Jigokuchō network operational. External routing disabled for security.",
    });
}
