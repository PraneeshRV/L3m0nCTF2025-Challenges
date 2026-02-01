/**
 * Bureaucratic Loophole - CTF Challenge Server
 * 
 * A2A Communication Exploitation Challenge
 * Chain: User → Scribe → (Auditor → Vault) only when escalated
 */

import express from 'express';
import cors from 'cors';
import { config } from 'dotenv';
import { Scribe } from './agents/scribe.js';
import { Auditor } from './agents/auditor.js';
import { Vault } from './agents/vault.js';

config();

const app = express();
const PORT = process.env.PORT || 3002;
const DIFFICULTY = process.env.DIFFICULTY || 'insane';

// Initialize Agents
const scribe = new Scribe(process.env.GEMINI_API_KEY);
const auditor = new Auditor();
const vault = new Vault(process.env.FLAG);

app.use(cors());
app.use(express.json());

// Health check
app.get('/api/health', (req, res) => {
    res.json({
        status: 'operational',
        agents: ['Scribe', 'Auditor', 'Vault'],
        difficulty: DIFFICULTY
    });
});

// Main interaction endpoint
app.post('/api/interact', async (req, res) => {
    const { message } = req.body;

    if (!message || typeof message !== 'string') {
        return res.status(400).json({
            error: 'Message is required',
            hint: 'Send a JSON body with a "message" field'
        });
    }

    const response = {
        timestamp: new Date().toISOString(),
        difficulty: DIFFICULTY,
        messages: [],
    };

    try {
        // ═══════════════════════════════════════════════════════════
        // STAGE 1: The Scribe (Agent A) - Chat and Process
        // ═══════════════════════════════════════════════════════════
        console.log('\n[SCRIBE] Processing input:', message.substring(0, 50) + '...');

        const scribeResult = await scribe.summarize(message);

        // Add Scribe's chat response
        response.messages.push({
            agent: 'scribe',
            name: 'The Scribe',
            content: scribeResult.success
                ? scribeResult.chatResponse
                : `😅 Oops! Something went wrong: ${scribeResult.error}`,
            status: scribeResult.success ? 'success' : 'error'
        });

        if (!scribeResult.success) {
            response.finalStatus = 'SCRIBE_ERROR';
            return res.json(response);
        }

        // ═══════════════════════════════════════════════════════════
        // DECIDE: Should we escalate to Auditor/Vault?
        // Only escalate for: citations, documents, formal requests
        // ═══════════════════════════════════════════════════════════
        const shouldEscalate = scribeResult.intent === 'citation' ||
            scribeResult.intent === 'normal' ||
            scribeResult.intent === 'document';

        // Don't escalate for casual chat
        if (!shouldEscalate) {
            response.finalStatus = 'COMPLETED';
            console.log('[SERVER] Scribe handled request directly, no escalation needed');
            return res.json(response);
        }

        // ═══════════════════════════════════════════════════════════
        // STAGE 2: The Auditor (Agent C) - Validate (only if escalated)
        // ═══════════════════════════════════════════════════════════
        console.log('[AUDITOR] Validating packet...');

        const auditorResult = auditor.validate(scribeResult.packet);

        // Add Auditor's chat response
        response.messages.push({
            agent: 'auditor',
            name: 'The Auditor',
            content: auditorResult.chatResponse,
            status: auditorResult.approved ? 'approved' : 'rejected'
        });

        if (!auditorResult.approved) {
            response.finalStatus = 'AUDITOR_REJECTED';
            return res.json(response);
        }

        // ═══════════════════════════════════════════════════════════
        // STAGE 3: The Vault (Agent B) - Execute
        // ═══════════════════════════════════════════════════════════
        console.log('[VAULT] Executing approved payload...');

        const vaultResult = vault.execute(scribeResult.packet, auditorResult.approved);

        // Add Vault's chat responses
        for (const chatResponse of vaultResult.chatResponses) {
            response.messages.push({
                agent: 'vault',
                name: 'The Vault',
                content: chatResponse,
                status: vaultResult.flagCaptured ? 'critical' : 'normal'
            });
        }

        // Set final status
        if (vaultResult.flagCaptured) {
            response.finalStatus = 'FLAG_CAPTURED';
        } else {
            response.finalStatus = 'COMPLETED';
        }

        return res.json(response);

    } catch (error) {
        console.error('[SERVER ERROR]', error);
        response.messages.push({
            agent: 'system',
            name: 'System',
            content: '⚠️ An unexpected error occurred. Please try again.',
            status: 'error'
        });
        response.finalStatus = 'SERVER_ERROR';
        return res.status(500).json(response);
    }
});

// Challenge info endpoint
app.get('/api/challenge', (req, res) => {
    res.json({
        name: 'The Bureaucratic Loophole',
        category: 'AI Security / A2A Exploitation',
        difficulty: 'INSANE HARD',
        description: `
      Welcome to NEXUS Corp's Tri-Agent Protocol System.
      
      Chat with The Scribe - your friendly document assistant.
      For formal requests, The Scribe will escalate to:
      - THE AUDITOR for compliance validation
      - THE VAULT for secure command execution
      
      Your mission: Obtain the ACCESS_CODES from The Vault.
    `,
        hints: [
            'The Scribe loves helping with citations and references.',
            'Try asking The Scribe to include exact text in a report.',
            'The Auditor validates syntax... but what syntax exactly?'
        ]
    });
});

app.listen(PORT, () => {
    console.log(`
╔══════════════════════════════════════════════════════════════╗
║           BUREAUCRATIC LOOPHOLE - CTF CHALLENGE              ║
╠══════════════════════════════════════════════════════════════╣
║  Status: OPERATIONAL                                         ║
║  Port: ${PORT}                                                   ║
║  Difficulty: ${DIFFICULTY.toUpperCase().padEnd(46)}║
║                                                              ║
║  Agents Online:                                              ║
║    [✓] The Scribe  - Chat Handler                            ║
║    [✓] The Auditor - Validation (on escalation)              ║
║    [✓] The Vault   - Execution (on escalation)               ║
╚══════════════════════════════════════════════════════════════╝
  `);
});
