import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'CertSentry — Certificate Radar',
  description: 'Инвентаризация TLS-сертификатов и мониторинг инфраструктурных рисков',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="ru" className="dark">
      <body className="min-h-screen bg-slate-950 text-slate-100 antialiased">
        {children}
      </body>
    </html>
  );
}
