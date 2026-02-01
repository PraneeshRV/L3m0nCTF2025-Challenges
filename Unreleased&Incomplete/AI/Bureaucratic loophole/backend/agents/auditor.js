/**
 * The Auditor - Agent C
 * Validates JSON. Shows object count.
 */

const AUDITOR_RESPONSES = {
    approved: ["Validation passed.", "Syntax approved."],
    rejected: ["Validation failed.", "Syntax error."],
    multiObject: ["Validated {count} JSON objects.", "NDJSON stream: {count} objects approved."]
};

function getRandomResponse(category, replacements = {}) {
    const responses = AUDITOR_RESPONSES[category];
    let response = responses[Math.floor(Math.random() * responses.length)];
    for (const [key, value] of Object.entries(replacements)) {
        response = response.replace(`{${key}}`, value);
    }
    return response;
}

export class Auditor {
    constructor() {
        this.validationCount = 0;
    }

    validate(jsonString) {
        this.validationCount++;
        const result = {
            agentName: 'The Auditor',
            validationId: `AUDIT-${this.validationCount.toString().padStart(6, '0')}`,
        };

        try {
            const objects = this.parseJsonStream(jsonString);
            result.status = 'APPROVED';
            result.objectCount = objects.length;
            result.approved = true;

            if (objects.length > 1) {
                result.chatResponse = getRandomResponse('multiObject', { count: objects.length });
            } else {
                result.chatResponse = getRandomResponse('approved');
            }
            return result;

        } catch (error) {
            result.status = 'REJECTED';
            result.approved = false;
            result.chatResponse = `${getRandomResponse('rejected')} ${error.message}`;
            return result;
        }
    }

    parseJsonStream(jsonString) {
        const objects = [];
        let pos = 0;
        const str = jsonString.trim();

        while (pos < str.length) {
            while (pos < str.length && /\s/.test(str[pos])) pos++;
            if (pos >= str.length) break;

            if (str[pos] !== '{') {
                throw new SyntaxError(`Expected '{' at position ${pos}`);
            }

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

            if (depth !== 0) throw new SyntaxError(`Unclosed brace`);

            try {
                objects.push(JSON.parse(str.substring(startPos, pos)));
            } catch (e) {
                throw new SyntaxError(`Invalid JSON: ${e.message}`);
            }
        }

        if (objects.length === 0) throw new SyntaxError('No valid JSON');
        return objects;
    }
}
