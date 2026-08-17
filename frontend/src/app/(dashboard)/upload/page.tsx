'use client';

import { useRef, useState, type DragEvent } from 'react';
import { useRouter } from 'next/navigation';
import { UploadCloud } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { PageHeader } from '@/components/ui/page-header';
import { useUpload } from '@/lib/hooks/use-jobs';
import { cn } from '@/lib/utils';

export default function UploadPage() {
  const router = useRouter();
  const upload = useUpload();
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const [file, setFile] = useState<File | null>(null);

  const pick = (f: File | null) => {
    if (f && (f.name.endsWith('.apk') || f.name.endsWith('.xapk'))) setFile(f);
  };

  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setDragging(false);
    pick(e.dataTransfer.files?.[0] ?? null);
  };

  const submit = () => {
    if (!file) return;
    upload.mutate(file, {
      onSuccess: (res) => router.push(`/tasks/${res.job_id}`),
    });
  };

  return (
    <div>
      <PageHeader title="Upload APK" description="Submit an Android APK for automated analysis." />

      <Card>
        <CardContent className="pt-6">
          <div
            onDragOver={(e) => {
              e.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={onDrop}
            onClick={() => inputRef.current?.click()}
            className={cn(
              'flex cursor-pointer flex-col items-center justify-center gap-3 rounded-lg border-2 border-dashed p-10 text-center transition-colors',
              dragging ? 'border-primary bg-muted/50' : 'border-input',
            )}
          >
            <UploadCloud className="h-10 w-10 text-muted-foreground" />
            <div>
              <p className="font-medium">
                {file ? file.name : 'Drop an APK here or click to browse'}
              </p>
              <p className="text-sm text-muted-foreground">.apk / .xapk files</p>
            </div>
            <input
              ref={inputRef}
              type="file"
              accept=".apk,.xapk"
              className="hidden"
              onChange={(e) => pick(e.target.files?.[0] ?? null)}
            />
          </div>

          {upload.isError && (
            <p className="mt-4 text-sm text-destructive">
              {upload.error instanceof Error ? upload.error.message : 'Upload failed.'}
            </p>
          )}

          <div className="mt-4 flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setFile(null)} disabled={!file}>
              Clear
            </Button>
            <Button onClick={submit} loading={upload.isPending} disabled={!file}>
              Start analysis
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
