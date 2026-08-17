import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import { Providers } from '@/lib/providers';
import '@/styles/globals.css';

export const metadata: Metadata = {
  title: 'Sephela — APK Risk Analysis',
  description: 'Automated analysis and risk scoring of fraudulent Android APKs.',
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="min-h-screen antialiased">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
