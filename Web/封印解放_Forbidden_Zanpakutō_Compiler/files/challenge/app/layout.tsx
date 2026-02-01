import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
    title: "鳳凰殿 Archive | Kidō Corps Restoration Division",
    description: "Classified Spiritual Document Reconstruction System",
};

export default function RootLayout({
    children,
}: Readonly<{
    children: React.ReactNode;
}>) {
    return (
        <html lang="ja">
            <body className="antialiased">
                <div className="reiatsu-particles" aria-hidden="true" />

                <nav className="fixed top-0 left-0 right-0 z-50 border-b border-seireitei-purple/30 bg-seireitei-deeper/80 backdrop-blur-md">
                    <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
                        <div className="flex items-center gap-3">
                            <div className="w-8 h-8 rounded-full bg-gradient-to-br from-seireitei-glow to-seireitei-purple flex items-center justify-center text-xs font-bold">
                                零
                            </div>
                            <span className="font-medium text-seireitei-text/90">鳳凰殿</span>
                        </div>

                        <div className="flex items-center gap-6 text-sm">
                            <a href="/" className="text-seireitei-muted hover:text-seireitei-text transition-colors">
                                Archives
                            </a>
                            <a href="/compiler" className="text-seireitei-muted hover:text-seireitei-text transition-colors">
                                Recompiler
                            </a>
                            <a href="/auth" className="text-seireitei-muted hover:text-seireitei-text transition-colors">
                                Authentication
                            </a>
                        </div>
                    </div>
                </nav>

                <main className="relative z-10 pt-20 min-h-screen">
                    {children}
                </main>

                <footer className="relative z-10 border-t border-seireitei-purple/20 bg-seireitei-deeper/50 py-6">
                    <div className="max-w-6xl mx-auto px-6 flex items-center justify-between text-xs text-seireitei-muted font-mono">
                        <span>© 護廷十三隊 · Kidō Corps Reconstruction Division</span>
                        <span className="opacity-60">瀞霊廷中央図書館</span>
                    </div>
                </footer>
            </body>
        </html>
    );
}
