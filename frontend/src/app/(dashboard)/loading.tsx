import { LoadingState } from '@/components/ui/feedback';

// Route-level loading UI for the dashboard group (Suspense fallback).
export default function Loading() {
  return <LoadingState />;
}
