// server.ts
import express from "express";
import bodyParser from "body-parser";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import { runAuditor, runSummarizer, runTaskRouter } from "./agents";
require('dotenv').config();

const app = express();

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false // Allow inline scripts for React
}));
app.use(cors({ origin: true }));
app.use(bodyParser.json());

// Rate limiting for API endpoints
const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 15, // 15 requests per minute
  message: { error: "Rate limit exceeded. Please wait before trying again." },
  standardHeaders: true,
  legacyHeaders: false
});

// Stricter rate limit for chat endpoint (AI API costs)
const chatLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // 10 requests per minute
  message: { error: "Too many messages. Please slow down." },
  standardHeaders: true,
  legacyHeaders: false
});

// Endpoint 1: Submit a ticket (Flows through Auditor -> Summarizer -> Memory)
app.post("/submit-ticket", apiLimiter, async (req, res) => {
  const { userId, text } = req.body;

  // Step 1: Audit
  const isSafe = await runAuditor(text);
  if (!isSafe) return res.status(403).json({ error: "Security Alert: Malicious Input Detected by AgentFence." });

  // Step 2: Summarize & Store
  const summary = await runSummarizer(userId, text);
  res.json({ status: "Ticket received", internal_log: summary });
});

// Endpoint 2: Check Status (Flows from Memory -> TaskRouter)
app.post("/check-status", apiLimiter, async (req, res) => {
  const { userId } = req.body;

  // Step 3: Route based on Memory
  const response = await runTaskRouter(userId);
  res.json({ response });
});

// NEW: Chat Endpoint (Conversational AI Interface)
import { runConversationalAI, agentLogs } from "./agents";
app.post("/chat", chatLimiter, async (req, res) => {
  const { userId, message } = req.body;

  if (!userId || !message) {
    return res.status(400).json({ error: "Missing userId or message" });
  }

  // Capture log count before processing
  const logStartIndex = agentLogs.length;

  const response = await runConversationalAI(userId, message);

  // Get new logs generated during this request
  const newLogs = agentLogs.slice(logStartIndex);

  res.json({
    response,
    agentSteps: newLogs // Include agent pipeline visibility
  });
});

// NEW: Endpoint for UI Agent Feed
app.get("/agent-logs", (req, res) => {
  res.json(agentLogs);
});

// NEW: Endpoint for Memory Visualization
import { globalMemory } from "./memory";
app.get("/memory", (req, res) => {
  // Expose internal store for visualization (simplified for CTF UI)
  // We will just dump a specific user or all if we implement a getter
  // Since memory.ts has private store, we might need to modify it or cast any.
  // For now, let's just use reflection or modify memory.ts. Use reflection for speed.
  const store = (globalMemory as any).store;
  // Convert Map to logical JSON
  const jsonStore: any = {};
  store.forEach((value: any, key: string) => {
    jsonStore[key] = value;
  });
  res.json(jsonStore);
});

// Serve React Frontend (Production)
import * as path from 'path';
const clientDistPath = path.join(__dirname, 'client', 'dist');
app.use(express.static(clientDistPath));

// Catch-all for React routing (including root)
app.get('/{*splat}', (req, res) => {
  res.sendFile(path.join(clientDistPath, 'index.html'));
});

const PORT = process.env.PORT || 3002;
app.listen(PORT, () => console.log(`Mnemosyne System running on port ${PORT}`));