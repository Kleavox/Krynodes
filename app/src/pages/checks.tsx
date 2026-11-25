import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { CheckList } from "@/features/checks/check-list";
import { useChecks } from "@/lib/api";
import { errorMessage } from "@/lib/http";

export function ChecksPage() {
  const checks = useChecks();
  const statusPage = checks.data?.statusPage;
  return (
    <>
      <PageHeader
        title="Checks"
        actions={
          statusPage && (
            <Button variant="outline" asChild>
              <a href={statusPage} target="_blank" rel="noreferrer">
                Status Page
              </a>
            </Button>
          )
        }
      />
      {checks.data ? (
        checks.data.checks.length === 0 ? (
          <EmptyState
            title="No checks yet"
            body="Add a check from a stack's menu on the Stacks page."
          />
        ) : (
          <CheckList checks={checks.data.checks} />
        )
      ) : checks.isError ? (
        <EmptyState
          title="The checks can't load"
          body={errorMessage(checks.error)}
          action={<Button onClick={() => void checks.refetch()}>Retry</Button>}
        />
      ) : (
        <div role="status" aria-label="Loading checks" className="space-y-2">
          <Skeleton className="h-14" />
          <Skeleton className="h-14" />
        </div>
      )}
    </>
  );
}
