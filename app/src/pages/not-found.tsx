import { Link } from "react-router";

import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { Button } from "@/components/ui/button";

export function NotFoundPage() {
  return (
    <>
      <PageHeader title="Page Not Found" />
      <EmptyState
        title="There is nothing at this address"
        body="Check the link, or go back to the fleet."
        action={
          <Button asChild variant="outline">
            <Link to="/">Back to Fleet</Link>
          </Button>
        }
      />
    </>
  );
}
