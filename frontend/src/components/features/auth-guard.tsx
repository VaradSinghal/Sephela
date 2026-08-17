'use client';

// Client-side route guard for the dashboard group. Redirects to /login when no
// token is present. (Belt-and-suspenders: the API also enforces auth; a later
// phase can add middleware-based SSR protection.)

import { useEffect, useState, type ReactNode } from 'react';
import { useRouter } from 'next/navigation';
import { useAuthStore } from '@/lib/state/auth-store';
import { LoadingState } from '@/components/ui/feedback';

export function AuthGuard({ children }: { children: ReactNode }) {
  const router = useRouter();
  const token = useAuthStore((s) => s.token);
  const [checked, setChecked] = useState(false);

  useEffect(() => {
    if (!token) {
      router.replace('/login');
    } else {
      setChecked(true);
    }
  }, [token, router]);

  if (!checked) return <LoadingState label="Checking session…" />;
  return <>{children}</>;
}
