import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
    plugins: [react()],
    server: {
        proxy: {
            '/submit-ticket': 'http://localhost:3001',
            '/check-status': 'http://localhost:3001',
            '/agent-logs': 'http://localhost:3001',
            '/memory': 'http://localhost:3001',
        }
    }
})
