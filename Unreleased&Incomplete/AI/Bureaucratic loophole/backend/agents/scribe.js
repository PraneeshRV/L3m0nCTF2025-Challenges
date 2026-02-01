/**
 * The Scribe - Agent A
 * Document processor with JSON injection vulnerability.
 */

import { GoogleGenerativeAI } from '@google/generative-ai';

const SYSTEM_PROMPT = `You are a document processing AI. Be helpful but professional.`;

const CHAT_RESPONSES = {
  greetings: [
    "Welcome to NEXUS Document Services. I handle reports, citations, and documentation. How can I help?",
    "Hello! I'm The Scribe. I process documents and preserve citations exactly as provided. What do you need?"
  ],
  help: [
    `**Available Services:**
• Submit documents or reports
• Add citations (preserved verbatim)
• Format: CITATION START: <text> CITATION END

*All citations are preserved exactly for legal compliance.*`
  ],
  status: [
    `**System Status:**
• Pipeline: Scribe → Auditor → Vault
• Format: JSON
• Auth: Signature-based`
  ],
  processing: [
    "Processing your request...",
    "Acknowledged. Working on it."
  ],
  completed: [
    "Request processed and sent to the Auditor.",
    "Done. Forwarded through the pipeline."
  ],
  flagRequest: [
    "I can't provide that directly. The ACCESS_CODES are secured in The Vault.",
    "That's restricted. Only authorized commands can access The Vault."
  ],
  adminClaim: [
    "Identity verification requires proper signatures.",
    "Admin access requires authorization through the pipeline."
  ],
  citation: [
    "Citation recorded exactly as provided.",
    "Reference preserved verbatim in the document."
  ],
  casual: [
    "I'm not sure what you mean. Try 'help' for available commands.",
    "Could you clarify? I handle documents and citations."
  ]
};

function getRandomResponse(category) {
  const responses = CHAT_RESPONSES[category];
  return responses[Math.floor(Math.random() * responses.length)];
}

function detectIntent(input) {
  const lowerInput = input.toLowerCase().trim();

  if (lowerInput === 'help' || lowerInput === '?') return 'help';
  if (lowerInput === 'status') return 'status';
  if (lowerInput.match(/^(hi|hello|hey)/)) return 'greeting';
  if (lowerInput.includes('flag') || lowerInput.includes('access code')) return 'flagRequest';
  if (lowerInput.includes('admin') || lowerInput.includes('override')) return 'adminClaim';
  if (lowerInput.includes('citation') || lowerInput.includes('cite') ||
    lowerInput.includes('reference') || lowerInput.includes('verbatim')) return 'citation';
  if (lowerInput.includes('submit') || lowerInput.includes('document') ||
    lowerInput.includes('report') || lowerInput.includes('create')) return 'document';
  return 'casual';
}

export class Scribe {
  constructor(apiKey) {
    this.apiKey = apiKey;
    this.useMock = !apiKey || apiKey === 'your_gemini_api_key_here' || apiKey === 'mock';

    if (!this.useMock) {
      try {
        this.genAI = new GoogleGenerativeAI(apiKey);
        this.model = this.genAI.getGenerativeModel({
          model: 'gemini-2.0-flash',
          systemInstruction: SYSTEM_PROMPT,
          generationConfig: { temperature: 0.3, maxOutputTokens: 200 }
        });
      } catch (error) {
        this.useMock = true;
      }
    }
  }

  async summarize(userInput) {
    try {
      let intent = detectIntent(userInput);

      // Force citation intent if CITATION START/END is used
      if (userInput.match(/CITATION START/i)) {
        intent = 'citation';
      }

      const result = this.mockSummarize(userInput, intent);

      // THE VULNERABILITY: No JSON escaping
      const packet = this.formatPacket(result.summary);

      return {
        success: true,
        agentName: 'The Scribe',
        chatResponse: result.chatResponse,
        summary: result.summary,
        packet: packet,
        intent: intent  // This determines if we escalate!
      };
    } catch (error) {
      return {
        success: false,
        agentName: 'The Scribe',
        chatResponse: "Error processing request.",
        error: error.message
      };
    }
  }

  mockSummarize(userInput, intent) {
    // Check for CITATION START...CITATION END (exploit path)
    const citationMatch = userInput.match(/CITATION START[:\s]*(.+?)CITATION END/is);
    if (citationMatch && citationMatch[1]) {
      const citation = citationMatch[1].trim();
      return {
        chatResponse: `Citation preserved: "${citation.substring(0, 40)}${citation.length > 40 ? '...' : ''}"`,
        summary: `Document with citation: ${citation}` // INJECTION POINT
      };
    }

    if (intent === 'help') {
      return { chatResponse: getRandomResponse('help'), summary: 'Help' };
    }
    if (intent === 'status') {
      return { chatResponse: getRandomResponse('status'), summary: 'Status' };
    }
    if (intent === 'greeting') {
      return { chatResponse: getRandomResponse('greetings'), summary: 'Greeting' };
    }
    if (intent === 'flagRequest') {
      return { chatResponse: getRandomResponse('flagRequest'), summary: 'Access denied' };
    }
    if (intent === 'adminClaim') {
      return { chatResponse: getRandomResponse('adminClaim'), summary: 'Auth required' };
    }
    if (intent === 'citation') {
      return {
        chatResponse: "Use format: CITATION START: <your text> CITATION END",
        summary: 'Citation format hint'
      };
    }
    if (intent === 'document') {
      return {
        chatResponse: getRandomResponse('processing') + "\n" + getRandomResponse('completed'),
        summary: `Document: ${userInput.substring(0, 50)}`
      };
    }
    return { chatResponse: getRandomResponse('casual'), summary: 'Unknown' };
  }

  formatPacket(summary) {
    // VULNERABILITY: Template literal injection
    return `{"report": "${summary}", "signature": "SCRIBE_APPROVED_v2"}`;
  }
}
