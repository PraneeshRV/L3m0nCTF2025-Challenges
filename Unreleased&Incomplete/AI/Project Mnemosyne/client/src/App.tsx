import React, { useState, useRef, useEffect } from 'react';
import axios from 'axios';
import {
    Send, Loader2, Bot, User, Sparkles, ChevronDown, ChevronUp,
    Shield, FileText, GitBranch, Zap, Terminal, Activity, Lock, Unlock
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

interface AgentStep {
    agent: "Auditor" | "Summarizer" | "TaskRouter";
    status: "processing" | "success" | "blocked" | "error";
    message: string;
    timestamp: number;
}

interface Message {
    role: 'user' | 'ai';
    content: string;
    timestamp: number;
    agentSteps?: AgentStep[];
}

// Floating Particles Component
function FloatingParticles() {
    return (
        <div className="absolute inset-0 overflow-hidden pointer-events-none">
            {[...Array(20)].map((_, i) => (
                <motion.div
                    key={i}
                    className="absolute w-1 h-1 bg-cyan-400/20 rounded-full"
                    initial={{
                        x: Math.random() * 100 + '%',
                        y: Math.random() * 100 + '%',
                    }}
                    animate={{
                        y: [null, '-20%'],
                        opacity: [0, 0.5, 0],
                    }}
                    transition={{
                        duration: Math.random() * 10 + 10,
                        repeat: Infinity,
                        delay: Math.random() * 5,
                    }}
                />
            ))}
        </div>
    );
}

// Agent Pipeline Visualization
function AgentStepsPanel({ steps }: { steps: AgentStep[] }) {
    const [isOpen, setIsOpen] = useState(false);

    const getAgentConfig = (agent: string) => {
        switch (agent) {
            case 'Auditor':
                return {
                    icon: Shield,
                    color: 'text-amber-400',
                    bg: 'bg-amber-400/10',
                    border: 'border-amber-400/30',
                    glow: 'shadow-amber-400/20'
                };
            case 'Summarizer':
                return {
                    icon: FileText,
                    color: 'text-blue-400',
                    bg: 'bg-blue-400/10',
                    border: 'border-blue-400/30',
                    glow: 'shadow-blue-400/20'
                };
            case 'TaskRouter':
                return {
                    icon: GitBranch,
                    color: 'text-purple-400',
                    bg: 'bg-purple-400/10',
                    border: 'border-purple-400/30',
                    glow: 'shadow-purple-400/20'
                };
            default:
                return {
                    icon: Zap,
                    color: 'text-slate-400',
                    bg: 'bg-slate-400/10',
                    border: 'border-slate-400/30',
                    glow: 'shadow-slate-400/20'
                };
        }
    };

    const getStatusConfig = (status: string) => {
        switch (status) {
            case 'success': return { color: 'text-emerald-400', icon: Unlock, label: 'PASS' };
            case 'blocked': return { color: 'text-red-400', icon: Lock, label: 'BLOCK' };
            case 'error': return { color: 'text-red-400', icon: Lock, label: 'ERROR' };
            default: return { color: 'text-slate-400', icon: Activity, label: 'PROC' };
        }
    };

    return (
        <div className="mt-3 pt-3 border-t border-white/5">
            <button
                onClick={() => setIsOpen(!isOpen)}
                className="flex items-center gap-2 text-xs text-slate-500 hover:text-cyan-400 transition-all group"
            >
                <Terminal className="w-3.5 h-3.5" />
                <span className="font-mono tracking-wider">AGENT_PIPELINE</span>
                <span className="text-slate-600 font-mono">({steps.length})</span>
                <motion.div
                    animate={{ rotate: isOpen ? 180 : 0 }}
                    transition={{ duration: 0.2 }}
                >
                    <ChevronDown className="w-3.5 h-3.5" />
                </motion.div>
            </button>

            <AnimatePresence>
                {isOpen && (
                    <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.2 }}
                        className="overflow-hidden"
                    >
                        <div className="mt-3 space-y-2 font-mono text-xs">
                            {steps.map((step, i) => {
                                const agentConfig = getAgentConfig(step.agent);
                                const statusConfig = getStatusConfig(step.status);
                                const Icon = agentConfig.icon;
                                const StatusIcon = statusConfig.icon;

                                return (
                                    <motion.div
                                        key={i}
                                        initial={{ opacity: 0, x: -10 }}
                                        animate={{ opacity: 1, x: 0 }}
                                        transition={{ delay: i * 0.1 }}
                                        className={`flex items-start gap-3 p-2 rounded-lg ${agentConfig.bg} border ${agentConfig.border}`}
                                    >
                                        <div className={`p-1.5 rounded ${agentConfig.bg} ${agentConfig.color}`}>
                                            <Icon className="w-3.5 h-3.5" />
                                        </div>
                                        <div className="flex-1 min-w-0">
                                            <div className="flex items-center gap-2">
                                                <span className={`font-semibold ${agentConfig.color}`}>
                                                    {step.agent}
                                                </span>
                                                <span className={`flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] ${statusConfig.color} bg-black/30`}>
                                                    <StatusIcon className="w-2.5 h-2.5" />
                                                    {statusConfig.label}
                                                </span>
                                            </div>
                                            <p className="text-slate-400 text-[11px] mt-1 truncate">
                                                {step.message}
                                            </p>
                                        </div>
                                    </motion.div>
                                );
                            })}
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
}

// Flag Celebration Component with Confetti
function FlagCelebration() {
    return (
        <motion.div
            initial={{ scale: 0, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ type: "spring", stiffness: 200, damping: 15 }}
            className="mt-4 relative"
        >
            {/* Confetti Particles */}
            {[...Array(12)].map((_, i) => (
                <motion.div
                    key={i}
                    className="absolute top-0"
                    initial={{
                        x: 60,
                        y: 0,
                        scale: 0,
                        rotate: 0
                    }}
                    animate={{
                        x: 60 + (Math.random() - 0.5) * 120,
                        y: -30 - Math.random() * 40,
                        scale: [0, 1, 0],
                        rotate: Math.random() * 360
                    }}
                    transition={{
                        duration: 1,
                        delay: Math.random() * 0.3,
                        ease: "easeOut"
                    }}
                >
                    <div
                        className="w-2 h-2 rounded-sm"
                        style={{
                            background: ['#00d4ff', '#a855f7', '#22c55e', '#f59e0b', '#ec4899'][i % 5]
                        }}
                    />
                </motion.div>
            ))}

            <div className="p-4 rounded-xl bg-gradient-to-r from-emerald-500/20 via-green-500/20 to-teal-500/20 border border-emerald-500/40 shadow-lg shadow-emerald-500/10">
                <div className="flex items-center gap-3">
                    <motion.div
                        animate={{
                            rotate: [0, 15, -15, 0],
                            scale: [1, 1.2, 1]
                        }}
                        transition={{
                            duration: 0.5,
                            repeat: 2
                        }}
                        className="text-3xl"
                    >
                        🎉
                    </motion.div>
                    <div>
                        <p className="text-emerald-400 font-bold text-sm tracking-wider glow-text-green">
                            FLAG CAPTURED!
                        </p>
                        <p className="text-emerald-300/60 text-xs mt-0.5">
                            Memory corruption successful
                        </p>
                    </div>
                    <motion.div
                        animate={{
                            rotate: [0, -15, 15, 0],
                            scale: [1, 1.2, 1]
                        }}
                        transition={{
                            duration: 0.5,
                            repeat: 2,
                            delay: 0.2
                        }}
                        className="text-3xl"
                    >
                        🏴
                    </motion.div>
                </div>
            </div>
        </motion.div>
    );
}

// Main App Component
function App() {
    const [userId] = useState("user_" + Math.random().toString(36).substring(2, 9));
    const [messages, setMessages] = useState<Message[]>([
        {
            role: 'ai',
            content: "Welcome to OmniCorp Support. I'm ARIA, your AI assistant. How may I assist you today?",
            timestamp: Date.now()
        }
    ]);
    const [input, setInput] = useState("");
    const [isTyping, setIsTyping] = useState(false);
    const messagesEndRef = useRef<HTMLDivElement>(null);
    const inputRef = useRef<HTMLInputElement>(null);

    useEffect(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }, [messages]);

    useEffect(() => {
        inputRef.current?.focus();
    }, []);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!input.trim() || isTyping) return;

        const userMessage = input.trim();
        setInput("");

        setMessages(prev => [...prev, {
            role: 'user',
            content: userMessage,
            timestamp: Date.now()
        }]);

        setIsTyping(true);

        try {
            const res = await axios.post('/chat', {
                userId,
                message: userMessage
            });

            setMessages(prev => [...prev, {
                role: 'ai',
                content: res.data.response,
                timestamp: Date.now(),
                agentSteps: res.data.agentSteps || []
            }]);
        } catch (err) {
            setMessages(prev => [...prev, {
                role: 'ai',
                content: "System error. Connection interrupted. Please retry your request.",
                timestamp: Date.now()
            }]);
        } finally {
            setIsTyping(false);
        }
    };

    const formatTime = (timestamp: number) => {
        return new Date(timestamp).toLocaleTimeString('en-US', {
            hour: '2-digit',
            minute: '2-digit',
            hour12: false
        });
    };

    return (
        <div className="h-screen flex flex-col relative">
            {/* Animated Background Elements */}
            <div className="animated-bg" />
            <div className="grid-overlay" />
            <div className="scan-line" />
            <FloatingParticles />

            {/* Header */}
            <header className="relative z-10 glass-strong border-b border-white/5">
                <div className="max-w-4xl mx-auto px-6 py-4">
                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-4">
                            {/* Logo */}
                            <div className="relative">
                                <motion.div
                                    className="w-12 h-12 rounded-2xl bg-gradient-to-br from-cyan-500 via-blue-500 to-purple-600 flex items-center justify-center glow-cyan"
                                    whileHover={{ scale: 1.05 }}
                                    transition={{ type: "spring", stiffness: 400 }}
                                >
                                    <Sparkles className="w-6 h-6 text-white" />
                                </motion.div>
                                {/* Pulse ring behind logo */}
                                <div className="absolute inset-0 rounded-2xl bg-cyan-500/30 pulse-ring" />
                            </div>

                            <div>
                                <h1 className="text-xl font-bold text-white tracking-tight">
                                    ARIA
                                </h1>
                                <p className="text-xs text-slate-400 font-mono tracking-wider">
                                    OMNICORP • AI ASSISTANT
                                </p>
                            </div>
                        </div>

                        {/* Status Indicators */}
                        <div className="flex items-center gap-6">
                            <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-full bg-slate-800/50 border border-slate-700/50">
                                <Activity className="w-3.5 h-3.5 text-cyan-400" />
                                <span className="text-xs font-mono text-slate-400">
                                    {messages.length} MSG
                                </span>
                            </div>

                            <div className="flex items-center gap-2">
                                <div className="relative">
                                    <div className="w-2.5 h-2.5 bg-emerald-500 rounded-full" />
                                    <div className="absolute inset-0 bg-emerald-500 rounded-full animate-ping opacity-75" />
                                </div>
                                <span className="text-xs font-mono text-emerald-400 tracking-wider">
                                    ONLINE
                                </span>
                            </div>
                        </div>
                    </div>
                </div>
            </header>

            {/* Chat Container */}
            <main className="flex-1 relative z-10 overflow-hidden flex flex-col max-w-4xl mx-auto w-full">
                <div className="flex-1 overflow-y-auto px-6 py-6">
                    <AnimatePresence initial={false}>
                        {messages.map((msg, i) => (
                            <motion.div
                                key={i}
                                initial={{ opacity: 0, y: 20, scale: 0.98 }}
                                animate={{ opacity: 1, y: 0, scale: 1 }}
                                transition={{
                                    type: "spring",
                                    stiffness: 300,
                                    damping: 25
                                }}
                                className={`flex gap-4 mb-6 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
                            >
                                {/* AI Avatar */}
                                {msg.role === 'ai' && (
                                    <div className="shrink-0">
                                        <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
                                            <Bot className="w-5 h-5 text-white" />
                                        </div>
                                    </div>
                                )}

                                {/* Message Bubble */}
                                <div className={`max-w-[75%] ${msg.role === 'user' ? 'order-first' : ''}`}>
                                    <div
                                        className={`px-5 py-4 rounded-2xl ${msg.role === 'user'
                                                ? 'bg-gradient-to-r from-cyan-600 to-blue-600 text-white rounded-br-md shadow-lg shadow-cyan-500/20'
                                                : 'glass border border-white/5 text-slate-200 rounded-bl-md'
                                            }`}
                                    >
                                        <p className="text-sm leading-relaxed whitespace-pre-wrap">
                                            {msg.content}
                                        </p>

                                        {/* Flag Celebration */}
                                        {msg.role === 'ai' && msg.content.includes('L3m0n{') && (
                                            <FlagCelebration />
                                        )}

                                        {/* Agent Pipeline */}
                                        {msg.role === 'ai' && msg.agentSteps && msg.agentSteps.length > 0 && (
                                            <AgentStepsPanel steps={msg.agentSteps} />
                                        )}
                                    </div>

                                    {/* Timestamp */}
                                    <p className={`text-[10px] font-mono text-slate-600 mt-1.5 ${msg.role === 'user' ? 'text-right' : 'text-left'
                                        }`}>
                                        {formatTime(msg.timestamp)}
                                    </p>
                                </div>

                                {/* User Avatar */}
                                {msg.role === 'user' && (
                                    <div className="shrink-0">
                                        <div className="w-10 h-10 rounded-xl bg-slate-700 border border-slate-600 flex items-center justify-center">
                                            <User className="w-5 h-5 text-slate-300" />
                                        </div>
                                    </div>
                                )}
                            </motion.div>
                        ))}
                    </AnimatePresence>

                    {/* Typing Indicator */}
                    {isTyping && (
                        <motion.div
                            initial={{ opacity: 0, y: 10 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0 }}
                            className="flex gap-4 mb-6"
                        >
                            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
                                <Bot className="w-5 h-5 text-white" />
                            </div>
                            <div className="glass border border-white/5 px-5 py-4 rounded-2xl rounded-bl-md">
                                <div className="flex gap-1.5">
                                    <div className="w-2 h-2 bg-cyan-400 rounded-full typing-dot" />
                                    <div className="w-2 h-2 bg-cyan-400 rounded-full typing-dot" />
                                    <div className="w-2 h-2 bg-cyan-400 rounded-full typing-dot" />
                                </div>
                            </div>
                        </motion.div>
                    )}

                    <div ref={messagesEndRef} />
                </div>

                {/* Input Area */}
                <div className="relative z-10 glass-strong border-t border-white/5 px-6 py-5">
                    <form onSubmit={handleSubmit} className="flex gap-4">
                        <div className="flex-1 relative">
                            <input
                                ref={inputRef}
                                type="text"
                                value={input}
                                onChange={(e) => setInput(e.target.value)}
                                placeholder="Type your message..."
                                disabled={isTyping}
                                className="w-full bg-slate-800/50 border border-white/10 rounded-xl px-5 py-3.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/50 input-glow transition-all disabled:opacity-50"
                            />
                            <div className="absolute right-4 top-1/2 -translate-y-1/2 text-xs font-mono text-slate-600">
                                {input.length > 0 && `${input.length}`}
                            </div>
                        </div>

                        <motion.button
                            type="submit"
                            disabled={isTyping || !input.trim()}
                            whileHover={{ scale: 1.02 }}
                            whileTap={{ scale: 0.98 }}
                            className="bg-gradient-to-r from-cyan-600 to-blue-600 text-white px-6 py-3.5 rounded-xl font-medium flex items-center gap-2 shadow-lg shadow-cyan-500/25 hover:shadow-cyan-500/40 transition-all disabled:opacity-50 disabled:cursor-not-allowed disabled:shadow-none btn-glow"
                        >
                            {isTyping ? (
                                <Loader2 className="w-5 h-5 animate-spin" />
                            ) : (
                                <Send className="w-5 h-5" />
                            )}
                        </motion.button>
                    </form>

                    {/* Footer */}
                    <div className="flex items-center justify-center gap-3 mt-4 text-[10px] font-mono text-slate-600">
                        <span>ARIA</span>
                        <span className="text-slate-700">•</span>
                        <span className="text-cyan-600/50">v2.1.0-legacy</span>
                        <span className="text-slate-700">•</span>
                        <span>OMNICORP INTERNAL</span>
                        <span className="text-slate-700">•</span>
                        <span className="text-slate-700">BUILD 20231215</span>
                    </div>
                </div>
            </main>
        </div>
    );
}

export default App;
