import type { Config } from "tailwindcss";

const config: Config = {
    content: [
        "./pages/**/*.{js,ts,jsx,tsx,mdx}",
        "./components/**/*.{js,ts,jsx,tsx,mdx}",
        "./app/**/*.{js,ts,jsx,tsx,mdx}",
    ],
    theme: {
        extend: {
            colors: {
                seireitei: {
                    dark: "#0a0a0f",
                    deeper: "#050508",
                    purple: "#2d1b4e",
                    glow: "#6b4c9a",
                    accent: "#9d7cd8",
                    text: "#e0def4",
                    muted: "#6e6a86",
                },
                reiatsu: {
                    blue: "#3b82f6",
                    hollow: "#dc2626",
                    shinigami: "#a855f7",
                },
            },
            fontFamily: {
                jp: ["Noto Serif JP", "serif"],
                mono: ["JetBrains Mono", "monospace"],
            },
            animation: {
                "pulse-glow": "pulseGlow 2s ease-in-out infinite",
                "spirit-drift": "spiritDrift 8s ease-in-out infinite",
            },
            keyframes: {
                pulseGlow: {
                    "0%, 100%": { opacity: "0.4" },
                    "50%": { opacity: "1" },
                },
                spiritDrift: {
                    "0%, 100%": { transform: "translateY(0) rotate(0deg)" },
                    "50%": { transform: "translateY(-10px) rotate(1deg)" },
                },
            },
        },
    },
    plugins: [],
};

export default config;
