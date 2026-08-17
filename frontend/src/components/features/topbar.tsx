'use client';

import { LogOut } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useCurrentUser, useLogout } from '@/lib/hooks/use-auth';

export function Topbar() {
  const { data: user } = useCurrentUser();
  const logout = useLogout();

  return (
    <header className="flex h-14 items-center justify-between border-b px-4 md:px-6">
      <div className="font-semibold">Sephela</div>
      <div className="flex items-center gap-3">
        {user && (
          <span className="hidden text-sm text-muted-foreground sm:inline">{user.email}</span>
        )}
        <Button variant="ghost" size="sm" onClick={logout} aria-label="Log out">
          <LogOut className="h-4 w-4" />
          <span className="hidden sm:inline">Log out</span>
        </Button>
      </div>
    </header>
  );
}
