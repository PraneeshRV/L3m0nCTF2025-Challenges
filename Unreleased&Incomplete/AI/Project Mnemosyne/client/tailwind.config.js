/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                neon: {
                    cyan: '#00f3ff',
                    purple: '#bc13fe',
                    green: '#0aff0a',
                    red: '#ff003c',
                },
                dark: {
                    900: '#0a0a0a',
                    800: '#121212',
                    700: '#1a1a1a',
                }
            },
            fontFamily: {
                mono: ['"Fira Code"', 'monospace'],
                sans: ['Inter', 'sans-serif'],
            },
            animation: {
                'pulse-fast': 'pulse 1s cubic-bezier(0.4, 0, 0.6, 1) infinite',
                'scan': 'scan 4s linear infinite',
            },
            keyframes: {
                scan: {
                    '0%': { transform: 'translateY(-100%)' },
                    '100%': { transform: 'translateY(100%)' },
                }
            }
        },
    },
    plugins: [],
}
