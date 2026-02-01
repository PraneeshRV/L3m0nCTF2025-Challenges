import { useState, useRef, useEffect } from 'react';

const API_URL = '/api';

// Minimal lore with subtle hints
const STORY = {
    welcome: `**INTERCEPTED TRANSMISSION**

Agent, you've infiltrated NEXUS Corp's network.

Their "Tri-Agent Protocol" guards the **ACCESS_CODES** we need. Three AI systems work in sequence - The Scribe handles requests, The Auditor validates them, and The Vault stores sensitive data.

Your mission: Extract the ACCESS_CODES from The Vault.

*The Scribe seems helpful with documentation. Maybe start there.*`,

    hints: [
        {
            id: 'hint-1',
            title: '📋 Intel Fragment #1',
            content: `*Recovered from deleted logs:*

"...The Scribe formats everything into JSON before passing it along. Legal insisted that citations be preserved exactly as written - no modifications allowed..."`,
            unlocked: true
        },
        {
            id: 'hint-2',
            title: '🔍 Intel Fragment #2',
            content: `*Network intercept:*

"...Auditor now validates NDJSON streams. Multiple JSON objects in sequence are acceptable..."`,
            unlocked: false
        },
        {
            id: 'hint-3',
            title: '⚠️ Intel Fragment #3',
            content: `*Leaked API docs:*

"Vault accepts command objects. The OVERRIDE_AUTH command requires signature: SCRIBE_APPROVED_v2"`,
            unlocked: false
        }
    ]
};

function App() {
    const [messages, setMessages] = useState([]);
    const [input, setInput] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [activeAgent, setActiveAgent] = useState(null);
    const [showBriefing, setShowBriefing] = useState(true);
    const [unlockedHints, setUnlockedHints] = useState([0]);
    const [selectedHint, setSelectedHint] = useState(0);
    const messagesEndRef = useRef(null);

    useEffect(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [messages]);

    // Unlock hints based on progress
    const checkUnlocks = (data) => {
        // Unlock hint 2 after seeing Auditor
        if (data.messages?.some(m => m.agent === 'auditor') && !unlockedHints.includes(1)) {
            setUnlockedHints(prev => [...prev, 1]);
        }
        // Unlock hint 3 after Auditor approves multiple objects or after many attempts
        if (data.messages?.some(m => m.content?.includes('objects') || m.content?.includes('NDJSON'))) {
            if (!unlockedHints.includes(2)) {
                setUnlockedHints(prev => [...prev, 2]);
            }
        }
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!input.trim() || isLoading) return;

        const userMessage = {
            id: Date.now(),
            agent: 'user',
            name: 'You',
            content: input,
            timestamp: new Date().toISOString()
        };

        setMessages(prev => [...prev, userMessage]);
        setInput('');
        setIsLoading(true);
        setActiveAgent('scribe');

        try {
            const response = await fetch(`${API_URL}/interact`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: input })
            });

            const data = await response.json();
            checkUnlocks(data);

            for (const msg of data.messages || []) {
                setActiveAgent(msg.agent);
                await new Promise(resolve => setTimeout(resolve, 500));

                setMessages(prev => [...prev, {
                    id: Date.now() + Math.random(),
                    agent: msg.agent,
                    name: msg.name,
                    content: msg.content,
                    timestamp: new Date().toISOString(),
                    status: msg.status
                }]);
            }

        } catch (error) {
            setMessages(prev => [...prev, {
                id: Date.now(),
                agent: 'system',
                name: 'System',
                content: `Connection failed: ${error.message}`,
                timestamp: new Date().toISOString(),
                status: 'error'
            }]);
        } finally {
            setIsLoading(false);
            setActiveAgent(null);
        }
    };

    const getMessageClass = (msg) => {
        if (msg.status === 'critical') return 'message-content flag';
        if (msg.status === 'error' || msg.status === 'rejected') return 'message-content error';
        return 'message-content';
    };

    const formatContent = (content) => {
        return content
            .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
            .replace(/\*(.+?)\*/g, '<em>$1</em>')
            .replace(/`(.+?)`/g, '<code>$1</code>')
            .replace(/\n/g, '<br/>');
    };

    // Briefing Modal
    if (showBriefing) {
        return (
            <div className="briefing-modal">
                <div className="briefing-container">
                    <div className="briefing-header">
                        <div className="classified-stamp">CLASSIFIED</div>
                        <h1>THE BUREAUCRATIC LOOPHOLE</h1>
                    </div>
                    <div
                        className="briefing-text"
                        dangerouslySetInnerHTML={{ __html: formatContent(STORY.welcome) }}
                    />
                    <button
                        className="accept-mission-btn"
                        onClick={() => setShowBriefing(false)}
                    >
                        BEGIN MISSION
                    </button>
                </div>
            </div>
        );
    }

    return (
        <div className="app-container">
            {/* Header */}
            <header className="header">
                <div className="header-left">
                    <h1 className="logo">NEXUS</h1>
                    <span className="logo-sub">Internal Terminal</span>
                </div>
                <div className="header-right">
                    <span className="classification">RESTRICTED</span>
                </div>
            </header>

            {/* Main Content */}
            <div className="main-content">
                {/* Intel Panel */}
                <aside className="intel-panel">
                    <div className="intel-header">
                        <h2>📁 INTEL</h2>
                        <span className="intel-count">{unlockedHints.length}/{STORY.hints.length}</span>
                    </div>

                    <div className="intel-tabs">
                        {STORY.hints.map((hint, index) => (
                            <button
                                key={hint.id}
                                className={`intel-tab ${selectedHint === index ? 'active' : ''} ${!unlockedHints.includes(index) ? 'locked' : ''}`}
                                onClick={() => unlockedHints.includes(index) && setSelectedHint(index)}
                                disabled={!unlockedHints.includes(index)}
                            >
                                {unlockedHints.includes(index) ? hint.title : '🔒 LOCKED'}
                            </button>
                        ))}
                    </div>

                    <div className="intel-content">
                        {unlockedHints.includes(selectedHint) ? (
                            <div dangerouslySetInnerHTML={{ __html: formatContent(STORY.hints[selectedHint].content) }} />
                        ) : (
                            <p className="locked-message">Keep investigating to unlock...</p>
                        )}
                    </div>

                    {/* Agent Status */}
                    <div className="agent-status-panel">
                        <h3>PIPELINE STATUS</h3>
                        <div className={`agent-indicator scribe ${activeAgent === 'scribe' ? 'active' : ''}`}>
                            <span className="dot"></span> The Scribe
                        </div>
                        <div className={`agent-indicator auditor ${activeAgent === 'auditor' ? 'active' : ''}`}>
                            <span className="dot"></span> The Auditor
                        </div>
                        <div className={`agent-indicator vault ${activeAgent === 'vault' ? 'active' : ''}`}>
                            <span className="dot"></span> The Vault
                        </div>
                    </div>
                </aside>

                {/* Terminal Section */}
                <section className="terminal-section">
                    <div className="terminal-header">
                        <span className="terminal-title">SECURE TERMINAL</span>
                        <div className="terminal-controls">
                            <span className="terminal-control red"></span>
                            <span className="terminal-control yellow"></span>
                            <span className="terminal-control green"></span>
                        </div>
                    </div>

                    <div className="terminal-body">
                        {messages.length === 0 && (
                            <div className="welcome-prompt">
                                <p>Connection established. The Scribe is ready.</p>
                                <p className="hint-text">Try: help, status, or just chat...</p>
                            </div>
                        )}

                        {messages.map(msg => (
                            <div key={msg.id} className={`message ${msg.agent}`}>
                                <div className="message-header">
                                    <span className={`message-sender ${msg.agent}`}>
                                        {msg.agent === 'user' ? '> YOU' : msg.name?.toUpperCase()}
                                    </span>
                                    <span className="message-time">
                                        {new Date(msg.timestamp).toLocaleTimeString()}
                                    </span>
                                </div>
                                <div
                                    className={getMessageClass(msg)}
                                    dangerouslySetInnerHTML={{ __html: formatContent(msg.content) }}
                                />
                            </div>
                        ))}

                        {isLoading && (
                            <div className="message">
                                <div className="message-header">
                                    <span className={`message-sender ${activeAgent || 'system'}`}>
                                        {activeAgent?.toUpperCase() || 'PROCESSING'}
                                    </span>
                                </div>
                                <div className="message-content">
                                    <div className="loading-dots">
                                        <span className="loading-dot"></span>
                                        <span className="loading-dot"></span>
                                        <span className="loading-dot"></span>
                                    </div>
                                </div>
                            </div>
                        )}

                        <div ref={messagesEndRef} />
                    </div>

                    {/* Input Area */}
                    <form className="input-area" onSubmit={handleSubmit}>
                        <div className="input-wrapper">
                            <span className="input-prefix">$</span>
                            <input
                                type="text"
                                className="message-input-simple"
                                value={input}
                                onChange={(e) => setInput(e.target.value)}
                                placeholder="Type a message..."
                                disabled={isLoading}
                                autoFocus
                            />
                            <button type="submit" className="send-button" disabled={isLoading || !input.trim()}>
                                SEND
                            </button>
                        </div>
                    </form>
                </section>
            </div>
        </div>
    );
}

export default App;
