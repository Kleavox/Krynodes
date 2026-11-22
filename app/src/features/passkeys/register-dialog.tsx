import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { Busy } from "@/components/busy";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { apiFetch } from "@/lib/http";
import { failure, registerDevice } from "@/lib/passkeys";
import { queryKeys } from "@/lib/query-client";
import type { RegisterOptions } from "@/types";

const guessName = () =>
  /Android|iPhone|iPad/u.test(navigator.userAgent) ? "Phone" : "Laptop";

export function RegisterDialog({ onClose }: { onClose: () => void }) {
  const client = useQueryClient();
  const [name, setName] = useState(guessName);
  const register = useMutation({
    mutationFn: async () => {
      const options = await apiFetch<RegisterOptions>(
        "/api/devices/register/options",
        { method: "POST" },
      );
      const typed = name.trim();
      const body = await registerDevice(options, typed || guessName(), {
        guessed: !typed || typed === guessName(),
      });
      return apiFetch("/api/devices/register", {
        method: "POST",
        body: JSON.stringify(body),
      });
    },
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: queryKeys.devices });
      onClose();
    },
  });

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add a Passkey</DialogTitle>
          <DialogDescription>
            Your passkey asks for your fingerprint, your face or a PIN: Windows
            Hello, Google Password Manager, iCloud Keychain, a phone, or a
            security key. A passkey that only takes a touch cannot join. Your
            device asks twice: once to create the passkey, once to prove it.
          </DialogDescription>
        </DialogHeader>
        <form
          id="register-passkey"
          className="space-y-2"
          onSubmit={(event) => {
            event.preventDefault();
            register.mutate();
          }}
        >
          <Label htmlFor="passkey-name">Passkey Name</Label>
          <Input
            id="passkey-name"
            value={name}
            maxLength={40}
            autoComplete="off"
            onChange={(event) => setName(event.target.value)}
          />
        </form>
        {register.error && (
          <p role="alert" className="text-sm text-destructive">
            {failure(register.error)}
          </p>
        )}
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            type="submit"
            form="register-passkey"
            disabled={register.isPending}
          >
            {register.isPending ? <Busy>Waiting</Busy> : "Create Passkey"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
