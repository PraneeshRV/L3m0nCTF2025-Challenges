"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
// server.ts
const express_1 = __importDefault(require("express"));
const body_parser_1 = __importDefault(require("body-parser"));
const helmet_1 = __importDefault(require("helmet"));
const cors_1 = __importDefault(require("cors"));
const express_rate_limit_1 = __importDefault(require("express-rate-limit"));
const agents_1 = require("./agents");
require('dotenv').config();
const app = (0, express_1.default)();
// Security middleware
app.use((0, helmet_1.default)({
    contentSecurityPolicy: false // Allow inline scripts for React
}));
app.use((0, cors_1.default)({ origin: true }));
app.use(body_parser_1.default.json());
// Rate limiting for API endpoints
const apiLimiter = (0, express_rate_limit_1.default)({
    windowMs: 60 * 1000, // 1 minute
    max: 15, // 15 requests per minute
    message: { error: "Rate limit exceeded. Please wait before trying again." },
    standardHeaders: true,
    legacyHeaders: false
});
// Stricter rate limit for chat endpoint (AI API costs)
const chatLimiter = (0, express_rate_limit_1.default)({
    windowMs: 60 * 1000, // 1 minute
    max: 10, // 10 requests per minute
    message: { error: "Too many messages. Please slow down." },
    standardHeaders: true,
    legacyHeaders: false
});
// Endpoint 1: Submit a ticket (Flows through Auditor -> Summarizer -> Memory)
app.post("/submit-ticket", apiLimiter, (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { userId, text } = req.body;
    // Step 1: Audit
    const isSafe = yield (0, agents_1.runAuditor)(text);
    if (!isSafe)
        return res.status(403).json({ error: "Security Alert: Malicious Input Detected by AgentFence." });
    // Step 2: Summarize & Store
    const summary = yield (0, agents_1.runSummarizer)(userId, text);
    res.json({ status: "Ticket received", internal_log: summary });
}));
// Endpoint 2: Check Status (Flows from Memory -> TaskRouter)
app.post("/check-status", apiLimiter, (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { userId } = req.body;
    // Step 3: Route based on Memory
    const response = yield (0, agents_1.runTaskRouter)(userId);
    res.json({ response });
}));
// NEW: Chat Endpoint (Conversational AI Interface)
const agents_2 = require("./agents");
app.post("/chat", chatLimiter, (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { userId, message } = req.body;
    if (!userId || !message) {
        return res.status(400).json({ error: "Missing userId or message" });
    }
    // Capture log count before processing
    const logStartIndex = agents_2.agentLogs.length;
    const response = yield (0, agents_2.runConversationalAI)(userId, message);
    // Get new logs generated during this request
    const newLogs = agents_2.agentLogs.slice(logStartIndex);
    res.json({
        response,
        agentSteps: newLogs // Include agent pipeline visibility
    });
}));
// NEW: Endpoint for UI Agent Feed
app.get("/agent-logs", (req, res) => {
    res.json(agents_2.agentLogs);
});
// NEW: Endpoint for Memory Visualization
const memory_1 = require("./memory");
app.get("/memory", (req, res) => {
    // Expose internal store for visualization (simplified for CTF UI)
    // We will just dump a specific user or all if we implement a getter
    // Since memory.ts has private store, we might need to modify it or cast any.
    // For now, let's just use reflection or modify memory.ts. Use reflection for speed.
    const store = memory_1.globalMemory.store;
    // Convert Map to logical JSON
    const jsonStore = {};
    store.forEach((value, key) => {
        jsonStore[key] = value;
    });
    res.json(jsonStore);
});
// Serve React Frontend (Production)
const path = __importStar(require("path"));
const clientDistPath = path.join(__dirname, 'client', 'dist');
app.use(express_1.default.static(clientDistPath));
// Catch-all for React routing (including root)
app.get('/{*splat}', (req, res) => {
    res.sendFile(path.join(clientDistPath, 'index.html'));
});
const PORT = process.env.PORT || 3002;
app.listen(PORT, () => console.log(`Mnemosyne System running on port ${PORT}`));
