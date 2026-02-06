"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/hooks/use-auth";
import { useCreateEnvironment } from "@/hooks/use-environments";
import { useToast } from "@/hooks/use-toast";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import type { KeyType } from "@/types/api";

export default function NewEnvironmentPage() {
  const router = useRouter();
  const { isAdmin } = useAuth();
  const { toast } = useToast();
  const createMutation = useCreateEnvironment();

  const [name, setName] = useState("");
  const [keyType, setKeyType] = useState<KeyType>("ed25519");
  const [userValidity, setUserValidity] = useState("8h");
  const [hostValidity, setHostValidity] = useState("90d");

  if (!isAdmin) {
    return (
      <div className="flex items-center justify-center py-12">
        <Card className="max-w-md">
          <CardHeader>
            <CardTitle>Access Denied</CardTitle>
            <CardDescription>
              You need administrator permissions to create environments.
            </CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!name) {
      toast({
        title: "Validation Error",
        description: "Environment name is required.",
        variant: "destructive",
      });
      return;
    }

    // Validate name format
    const namePattern = /^[a-z0-9][a-z0-9-]*[a-z0-9]$|^[a-z0-9]$/;
    if (!namePattern.test(name)) {
      toast({
        title: "Validation Error",
        description: "Name must be lowercase alphanumeric with hyphens only.",
        variant: "destructive",
      });
      return;
    }

    try {
      await createMutation.mutateAsync({
        name,
        key_type: keyType,
        default_user_cert_validity: userValidity,
        default_host_cert_validity: hostValidity,
      });

      toast({
        title: "Environment Created",
        description: `Environment "${name}" has been created with new CA keypairs.`,
      });

      router.push(`/admin/environments/${name}`);
    } catch (error) {
      toast({
        title: "Error",
        description: error instanceof Error ? error.message : "Failed to create environment",
        variant: "destructive",
      });
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">New Environment</h1>
        <p className="text-muted-foreground">
          Create a new environment with dedicated CA keypairs.
        </p>
      </div>

      <Card className="max-w-2xl">
        <CardHeader>
          <CardTitle>Environment Configuration</CardTitle>
          <CardDescription>
            This will generate new User CA and Host CA keypairs for the environment.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name">Environment Name *</Label>
              <Input
                id="name"
                placeholder="prod, staging, dev"
                value={name}
                onChange={(e) => setName(e.target.value.toLowerCase())}
              />
              <p className="text-xs text-muted-foreground">
                Lowercase alphanumeric with hyphens. Examples: prod, staging, customer-prod
              </p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="keyType">Key Type</Label>
              <Select value={keyType} onValueChange={(v) => setKeyType(v as KeyType)}>
                <SelectTrigger id="keyType">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="ed25519">Ed25519 (Recommended)</SelectItem>
                  <SelectItem value="ecdsa">ECDSA</SelectItem>
                  <SelectItem value="rsa">RSA</SelectItem>
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                Algorithm for CA keypair generation. Ed25519 is recommended for performance and security.
              </p>
            </div>

            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="userValidity">Default User Cert Validity</Label>
                <Select value={userValidity} onValueChange={setUserValidity}>
                  <SelectTrigger id="userValidity">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="1h">1 hour</SelectItem>
                    <SelectItem value="4h">4 hours</SelectItem>
                    <SelectItem value="8h">8 hours</SelectItem>
                    <SelectItem value="12h">12 hours</SelectItem>
                    <SelectItem value="24h">24 hours</SelectItem>
                    <SelectItem value="7d">7 days</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="hostValidity">Default Host Cert Validity</Label>
                <Select value={hostValidity} onValueChange={setHostValidity}>
                  <SelectTrigger id="hostValidity">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="30d">30 days</SelectItem>
                    <SelectItem value="90d">90 days</SelectItem>
                    <SelectItem value="180d">180 days</SelectItem>
                    <SelectItem value="365d">365 days</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="flex gap-4 pt-4">
              <Button type="submit" disabled={createMutation.isPending}>
                {createMutation.isPending ? "Creating..." : "Create Environment"}
              </Button>
              <Button
                type="button"
                variant="outline"
                onClick={() => router.back()}
              >
                Cancel
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
