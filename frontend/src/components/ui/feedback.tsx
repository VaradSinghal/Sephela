// Shared loading / error / empty states — used across every data view so the
// dashboard has consistent async UX (docs requirement: loading + error states).

import { AlertCircle, Inbox, Loader2 } from 'lucide-react';
import type { ReactNode } from 'react';
import { ApiError } from '@/lib/api/client';
import { cn } from '@/lib/utils';

export function Spinner({ className }: { className?: string }) {
  return <Loader2 className={cn('h-5 w-5 animate-spin text-muted-foreground', className)} />;
}

export function LoadingState({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-16 text-muted-foreground">
      <Spinner />
      <span>{label}</span>
    </div>
  );
}

export function ErrorState({ error, retry }: { error: unknown; retry?: () => void }) {
  const message =
    error instanceof ApiError
      ? error.message
      : error instanceof Error
        ? error.message
        : 'Something went wrong.';
  const traceId = error instanceof ApiError ? error.traceId : null;

  return (
    <div className="flex flex-col items-center justify-center gap-3 py-16 text-center">
      <AlertCircle className="h-8 w-8 text-destructive" />
      <p className="font-medium">{message}</p>
      {traceId && <p className="text-xs text-muted-foreground">Trace ID: {traceId}</p>}
      {retry && (
        <button onClick={retry} className="text-sm text-primary underline underline-offset-4">
          Try again
        </button>
      )}
    </div>
  );
}

export function EmptyState({ title, description }: { title: string; description?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-16 text-center">
      <Inbox className="h-8 w-8 text-muted-foreground" />
      <p className="font-medium">{title}</p>
      {description && <p className="text-sm text-muted-foreground">{description}</p>}
    </div>
  );
}
