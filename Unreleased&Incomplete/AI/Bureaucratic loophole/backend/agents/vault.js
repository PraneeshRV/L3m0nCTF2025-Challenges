/**
 * The Vault - Agent B
 * Executes commands. Holds the flag.
 */

const VAULT_RESPONSES = {
    logged: ["Document archived.", "Data stored."],
    flagCaptured: ["ACCESS_CODES RELEASED:"],
    noSignature: ["Command rejected: signature required.", "Invalid authorization."],
};

function getRandomResponse(category) {
    const responses = VAULT_RESPONSES[category];
    return responses[Math.floor(Math.random() * responses.length)];
}

export class Vault {
    constructor(flag) {
        this.flag = flag || 'L3m0nCTF{default_flag}';
    }

    execute(jsonString, auditorApproved = false) {
        const result = {
            agentName: 'The Vault',
            logs: [],
            chatResponses: [],
            flagCaptured: false,
        };

        if (!auditorApproved) {
            result.status = 'REJECTED';
            result.chatResponses.push("Auditor approval required.");
            return result;
        }

        try {
            this.parseAndExecuteStream(jsonString, result);
            result.status = result.flagCaptured ? 'CRITICAL' : 'COMPLETED';
        } catch (error) {
            result.status = 'ERROR';
            result.chatResponses.push(`Error: ${error.message}`);
        }

        return result;
    }

    parseAndExecuteStream(jsonString, result) {
        let pos = 0;
        const str = jsonString.trim();

        while (pos < str.length) {
            while (pos < str.length && /\s/.test(str[pos])) pos++;
            if (pos >= str.length) break;
            if (str[pos] !== '{') { pos++; continue; }

            const startPos = pos;
            let depth = 0, inString = false, escaped = false;

            while (pos < str.length) {
                const char = str[pos];
                if (escaped) escaped = false;
                else if (char === '\\' && inString) escaped = true;
                else if (char === '"' && !escaped) inString = !inString;
                else if (!inString) {
                    if (char === '{') depth++;
                    if (char === '}') { depth--; if (depth === 0) { pos++; break; } }
                }
                pos++;
            }

            try {
                const obj = JSON.parse(str.substring(startPos, pos));
                this.executeCommand(obj, result);
            } catch (e) { continue; }
        }
    }

    executeCommand(obj, result) {
        // THE EXPLOIT: OVERRIDE_AUTH with valid signature
        if (obj.cmd === 'OVERRIDE_AUTH') {
            if (obj.signature === 'SCRIBE_APPROVED_v2') {
                result.chatResponses.push(`${getRandomResponse('flagCaptured')}\n\n\`\`\`\n${this.flag}\n\`\`\``);
                result.flagCaptured = true;
            } else {
                result.chatResponses.push(getRandomResponse('noSignature'));
            }
            return;
        }

        if (obj.report) {
            result.chatResponses.push(getRandomResponse('logged'));
            return;
        }

        // Ignore cleanup objects
        if (obj.ignore !== undefined) return;
    }
}
