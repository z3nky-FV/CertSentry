import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'CertSentry — TLS Governance & Monitoring',
  description: 'Мониторинг TLS-сертификатов, оценка инфраструктурных рисков и контроль изменений.',
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
