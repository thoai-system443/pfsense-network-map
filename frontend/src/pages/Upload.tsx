import { useMutation } from "@tanstack/react-query";
import { AlertTriangle, FileUp } from "lucide-react";
import { useNavigate } from "react-router-dom";

import { Button } from "@/components/ui/button";
import { uploadConfig } from "@/lib/api";
import type { ConfigMeta } from "@/lib/types";

export function UploadPage() {
  const navigate = useNavigate();
  const mutation = useMutation<ConfigMeta, Error, File>({
    mutationFn: uploadConfig,
    onSuccess: (meta) => {
      // Warnings mean the parser met something it did not recognise, so the
      // results may be incomplete. Stop and make the user look before moving on.
      if (meta.warnings.length === 0) {
        navigate(`/c/${meta.config_id}/topology`);
      }
    },
  });

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <section className="space-y-2">
        <h1 className="text-2xl font-semibold tracking-tight">Load a pfSense backup</h1>
        <p className="text-sm text-muted-foreground">
          The file is parsed in memory and never written to disk. Restarting the backend clears it.
        </p>
      </section>

      <label
        htmlFor="config-file"
        className="flex h-44 cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border-2 border-dashed border-input bg-card text-sm transition-colors duration-150 hover:border-primary hover:bg-muted"
      >
        <FileUp className="size-6 text-muted-foreground" aria-hidden="true" />
        <span className="font-medium">Choose a config.xml backup</span>
        <span className="text-muted-foreground">or drop it here</span>
        <input
          id="config-file"
          type="file"
          accept=".xml,text/xml"
          className="sr-only"
          onChange={(event) => {
            const file = event.target.files?.[0];
            if (file) mutation.mutate(file);
          }}
        />
      </label>

      {mutation.isPending && <p className="text-sm text-muted-foreground">Parsing…</p>}

      {mutation.isError && (
        <div
          role="alert"
          className="rounded-md border border-destructive bg-card p-4 text-sm text-destructive"
        >
          {mutation.error.message}
        </div>
      )}

      {mutation.isSuccess && (
        <section className="space-y-4">
          <dl className="flex flex-wrap gap-6 rounded-md border bg-card p-4 text-sm">
            <div>
              <dt className="text-xs uppercase tracking-wide text-muted-foreground">Version</dt>
              <dd className="tabular">{mutation.data.version ?? "unknown"}</dd>
            </div>
            {Object.entries(mutation.data.counts).map(([key, value]) => (
              <div key={key}>
                <dt className="text-xs uppercase tracking-wide text-muted-foreground">
                  {key.replace(/_/g, " ")}
                </dt>
                <dd className="tabular">{value}</dd>
              </div>
            ))}
          </dl>

          {mutation.data.warnings.length > 0 && (
            <div className="space-y-3 rounded-md border border-accent bg-card p-4">
              <div className="flex items-center gap-2">
                <AlertTriangle className="size-4 text-accent" aria-hidden="true" />
                <h2 className="font-medium">
                  {mutation.data.warnings.length} thing(s) the parser did not recognise
                </h2>
              </div>
              <p className="text-sm text-muted-foreground">
                These parts of the file were ignored, so results may be incomplete. This is the
                signal to check before trusting anything below.
              </p>
              <ul className="max-h-64 space-y-1 overflow-auto text-sm">
                {mutation.data.warnings.map((warning, index) => (
                  <li key={`${warning.path}-${index}`}>
                    <code className="text-xs">{warning.path}</code>{" "}
                    <span className="text-muted-foreground">— {warning.message}</span>
                  </li>
                ))}
              </ul>
              <Button
                type="button"
                onClick={() => navigate(`/c/${mutation.data.config_id}/topology`)}
              >
                Continue anyway
              </Button>
            </div>
          )}
        </section>
      )}
    </div>
  );
}
