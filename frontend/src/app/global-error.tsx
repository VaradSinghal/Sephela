'use client';

import { Button } from '@/components/ui/button';

// Top-level error boundary (docs requirement: error handling).
export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <html lang="en">
      <body className="flex min-h-screen items-center justify-center bg-background text-foreground">
        <div className="flex flex-col items-center gap-4 text-center">
          <h1 className="text-2xl font-semibold">Something went wrong</h1>
          <p className="max-w-md text-sm text-muted-foreground">{error.message}</p>
          <Button onClick={reset}>Try again</Button>
        </div>
      </body>
    </html>
  );
}
