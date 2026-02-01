/* * ==========================================================================
 * SYSTEM KERNEL: AGENT_45_OS (v4.5.1)
 * SECURITY LEVEL: MAX
 * ==========================================================================
 */

// [1] STRING TABLE (Obfuscated)
const _0xSTR = [
    "latency", "ROOT_OVERRIDE", "guest", "BLACK_WATCH_NODE_07", "4.5.1-stable",
    "color: #00f3ff; font-family: monospace;",
    "color: #ff0055; font-weight: bold; font-family: monospace;",
    "color: #ffcc00; font-family: monospace;",
    "color: #00ff66; font-weight: bold; font-family: monospace;",
    "color: #b300ff; font-family: monospace; text-shadow: 0 0 5px #b300ff;",
    "root:x:0:0:root:/root:/bin/bash\nagent45:x:1001:1001::/home/agent45:/bin/zsh",
    "[PERMISSION DENIED]",
    "TARGET: Project Chimera.\nSTATUS: Active.\nDIRECTIVE: Locate the encoded entry vector.",
    "To access the legacy vault, I need to reverse the base64 string in the debug module.",
    "console.log('Payload delivery system pending...');",
    "Dec 15 04:01:00 auth.err: Invalid credentials provided.",
    "0x53 0x45 0x43 0x52 0x45 0x54 0x5F 0x4B 0x45 0x59",
    "AES-256-CBC",
    "YWdlbnQ0NV9hY2Nlc3NfZ3JhbnRlZA==", // The Base64 Password
    "BIOS CHECK... OK", "LOADING KERNEL MODULES...", "MOUNTING VIRTUAL FILE SYSTEM..."
];

// Helper to fetch strings
const _S = (i) => _0xSTR[i];

// [2] CONFIG & MOCK FS
const _0xCFG = {
    _lat: 50,
    _ru: _S(1),
    _cu: _S(2),
    _hn: _S(3),
    _v: _S(4)
};

// The "Legacy" artifact (The flag/password container)
const _0xHIDDEN = [_S(18)];

const _0xFS = {
    "/": {
        "type": "dir",
        "children": {
            "bin": {
                "type": "dir",
                "children": {
                    "sh": { "type": "bin" },
                    "ls": { "type": "bin" },
                    "cat": { "type": "bin" },
                    "decrypt": { "type": "bin", "protected": true }
                }
            },
            "etc": {
                "type": "dir",
                "children": {
                    "passwd": { "type": "file", "content": _S(10) },
                    "shadow": { "type": "file", "content": _S(11), "protected": true }
                }
            },
            "home": {
                "type": "dir",
                "children": {
                    "agent45": {
                        "type": "dir",
                        "children": {
                            "mission_brief.txt": { "type": "file", "content": _S(12) },
                            "notes.md": { "type": "file", "content": _S(13) },
                            "payload.js": { "type": "file", "content": _S(14) }
                        }
                    }
                }
            },
            "var": {
                "type": "dir",
                "children": {
                    "logs": {
                        "type": "dir",
                        "children": { "syslog": { "type": "file", "content": _S(15) } }
                    },
                    "secure": {
                        "type": "dir",
                        "children": {
                            "vault.dat": {
                                "type": "file",
                                "content": _S(16),
                                "encrypted": true,
                                "encryption_method": _S(17)
                            }
                        }
                    }
                }
            }
        }
    }
};

// [3] UTILS
const _0xSTY = {
    sys: _S(5), err: _S(6), warn: _S(7), suc: _S(8), enc: _S(9)
};

class _0xUtils {
    static async wait(ms) { return new Promise(r => setTimeout(r, ms)); }
    static time() { return new Date().toISOString().replace('T', ' ').substring(0, 19); }
    static hex(inp) {
        let o = "";
        for (let i = 0; i < inp.length; i++) o += ("00" + inp.charCodeAt(i).toString(16).toUpperCase()).slice(-2) + " ";
        return o.trim();
    }
    static log(m, s = _0xSTY.sys) { console.log(`%c[${this.time()}] ${m}`, s); }
}

// [4] CORE ENIGMA (Crypto Engine)
class _0xEnigma {
    decode(_0xIn) {
        try { return atob(_0xIn); } catch (e) { return "ERR_DECODE"; }
    }
    analyze(_0xArr) {
        _0xUtils.log("Analyzing signature...", _0xSTY.warn);
        if (Array.isArray(_0xArr) && _0xArr.length > 0) {
            const _dec = this.decode(_0xArr[0]);
            console.groupCollapsed("%c[ ANALYTICS RESULT ]", _0xSTY.suc);
            console.log("Vector:", _0xArr[0]);
            console.log("Decoded:", _dec);
            console.groupEnd();
            return _dec;
        }
        return false;
    }
}

// [5] KERNEL
class _0xKernel {
    constructor() {
        this.fs = _0xFS;
        this.path = ["home", "agent45"];
        this.crypt = new _0xEnigma();
        this.live = false;
    }

    async boot() {
        // Control Flow Flattening Example
        let _step = 0;
        const _flow = [
            async () => { console.clear(); _0xUtils.log(_S(15), _0xSTY.sys); }, // BIOS
            async () => { await _0xUtils.wait(200); _0xUtils.log(_S(16), _0xSTY.sys); }, // LOAD
            async () => { await _0xUtils.wait(300); _0xUtils.log(_S(17), _0xSTY.sys); }, // MOUNT
            async () => {
                console.log(`%c
   ▄████████  ▄██████▄     ▄████████ ███▄▄▄▄      ███        
  ███    ███ ███    ███   ███    ███ ███▀▀▀██▄▀█████████▄    
  ███    ███ ███    █▀    ███    █▀  ███   ███    ▀███▀▀██   
  ███    ███ ███         ▄███▄▄▄     ███   ███     ███   ▀   
▀███████████ ███  ▀████ ▀▀███▀▀▀     ███   ███     ███       
  ███    ███ ███    ███   ███    █▄  ███   ███     ███       
  ███    ███ ███    ███   ███    ███ ███   ███     ███       
  ███    █▀  ▀██████▀     ██████████  ▀█   █▀     ▄████▀     
                                           TERMINAL v4.5     
        `, "color: #00f3ff; font-weight: bold;");
                this.live = true;
                this.prompt();
            }
        ];

        for (let _fn of _flow) { await _fn(); }
    }

    _resolve() {
        let c = this.fs["/"];
        for (let p of this.path) {
            if (c.children && c.children[p]) c = c.children[p];
            else return null;
        }
        return c;
    }

    async exec(_cmdStr) {
        if (!this.live) return;
        const args = _cmdStr.split(" ");
        const cmd = args[0].toLowerCase();

        _0xUtils.log(`EXEC: ${_cmdStr}`, "color: #aaa");

        // Obfuscated Switch
        const _cmds = {
            "help": () => this._help(),
            "ls": () => this._ls(),
            "cat": () => this._cat(args[1]),
            "cd": () => this._cd(args[1]),
            "pwd": () => console.log(`%c/${this.path.join("/")}`, _0xSTY.suc),
            "decrypt": async () => await this._dec(args[1]),
            "scan": async () => await this._scan(),
            "clear": () => console.clear()
        };

        if (_cmds[cmd]) await _cmds[cmd]();
        else _0xUtils.log(`ERR: Unkown opcode [${cmd}]`, _0xSTY.err);

        this.prompt();
    }

    _help() {
        console.table([
            { c: "ls", d: "List" }, { c: "cd", d: "Change Dir" },
            { c: "cat", d: "Read" }, { c: "scan", d: "Net Scan" },
            { c: "decrypt", d: "Cryptanalysis" }, { c: "clear", d: "CLS" }
        ]);
    }

    _ls() {
        const d = this._resolve();
        if (d && d.children) {
            console.table(Object.keys(d.children).map(n => ({
                Perm: d.children[n].protected ? "r--" : "rw-",
                Type: d.children[n].type === "dir" ? "DIR" : "FILE",
                Name: n
            })));
        } else _0xUtils.log("Read Error", _0xSTY.err);
    }

    _cat(fn) {
        const d = this._resolve();
        if (d.children && d.children[fn]) {
            const f = d.children[fn];
            if (f.type === "dir") return _0xUtils.log("Is Directory", _0xSTY.err);
            if (f.encrypted) {
                _0xUtils.log("ENCRYPTED. Use 'decrypt'.", _0xSTY.enc);
                console.log(`DUMP: ${_0xUtils.hex(f.content)}`);
                return;
            }
            console.log(`%c${f.content}`, "color: #fff; background: #222; padding: 5px;");
        } else _0xUtils.log("404 Not Found", _0xSTY.err);
    }

    _cd(t) {
        if (t === "..") { if (this.path.length > 0) this.path.pop(); }
        else {
            const c = this._resolve();
            if (c.children && c.children[t] && c.children[t].type === "dir") this.path.push(t);
            else _0xUtils.log("Invalid Path", _0xSTY.err);
        }
    }

    async _dec(t) {
        _0xUtils.log("INIT BRUTEFORCE...", _0xSTY.warn);
        await _0xUtils.wait(500);

        if (t === "vault.dat" && this.path.includes("secure")) {
            console.log("%c[SUCCESS] AES Key: 0xDEADBEEF", _0xSTY.suc);
            return;
        }

        // Hacking Logic
        if (typeof _0xHIDDEN !== 'undefined') {
            const r = this.crypt.analyze(_0xHIDDEN);
            if (r) {
                _0xUtils.log(`HASH BROKEN: ${r}`, _0xSTY.suc);
                window.agent_cred = r;
            }
        } else _0xUtils.log("Target Locked.", _0xSTY.err);
    }

    async _scan() {
        console.log("%cScanning...", _0xSTY.sys);
        await _0xUtils.wait(1000);
        console.log(`%c192.168.1.45:22 [OPEN]`, _0xSTY.suc);
        console.log(`%c10.0.0.1:443 [FILTERED]`, _0xSTY.err);
    }

    prompt() {
        console.log(`%c╭─${_0xCFG._cu}@${_0xCFG._hn} [ /${this.path.join("/")} ]`, "color: #00f3ff; font-weight: bold; margin-top: 10px;");
        console.log("%c╰─$ ", "color: #00f3ff; font-weight: bold;");
    }
}

// [6] INIT
const _OS = new _0xKernel();
window.run = async (c) => await _OS.exec(c);

// Auto-start
setTimeout(() => _OS.boot(), 1000);