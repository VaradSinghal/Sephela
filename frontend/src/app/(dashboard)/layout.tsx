import type { ReactNode } from 'react';
import { AuthGuard } from '@/components/features/auth-guard';
import { Sidebar } from '@/components/features/sidebar';
import { Topbar } from '@/components/features/topbar';

// Responsive dashboard shell: sidebar collapses on small screens.
export default function DashboardLayout({ children }: { children: ReactNode }) {
  return (
    <AuthGuard>
      <div className="flex min-h-screen flex-col">
        <Topbar />
        <div className="flex flex-1">
          <aside className="hidden w-56 shrink-0 border-r md:block">
            <Sidebar />
          </aside>
          <main className="flex-1 p-4 md:p-6">
            <div className="mx-auto max-w-6xl">{children}</div>
          </main>
        </div>
      </div>
    </AuthGuard>
  );
}
