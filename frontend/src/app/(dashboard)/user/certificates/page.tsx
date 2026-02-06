"use client";

import { useState } from "react";
import { useAuth } from "@/hooks/use-auth";
import { useEnvironments } from "@/hooks/use-environments";
import { useCertificates } from "@/hooks/use-certificates";
import { CertificateTable } from "@/components/certificates/certificate-table";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Label } from "@/components/ui/label";

export default function MyCertificatesPage() {
  const { user, accessibleEnvironments, isAdmin } = useAuth();
  const { data: envData, isLoading: envsLoading } = useEnvironments();
  const [selectedEnv, setSelectedEnv] = useState<string>("");

  const {
    data: certData,
    isLoading: certsLoading,
  } = useCertificates(selectedEnv, {
    include_expired: true,
    include_revoked: true,
  });

  // Filter certificates by current user's key_id (email)
  const myCertificates = certData?.certificates.filter(
    (cert) => cert.key_id === user?.email || cert.issued_by === user?.email
  ) || [];

  const environments = envData?.environments || [];
  const filteredEnvironments = isAdmin
    ? environments
    : environments.filter((env) => accessibleEnvironments.includes(env.name));

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">My Certificates</h1>
        <p className="text-muted-foreground">
          View certificates that have been issued to you.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Filter by Environment</CardTitle>
          <CardDescription>
            Select an environment to view your certificates.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="max-w-sm">
            <Label htmlFor="environment">Environment</Label>
            <Select value={selectedEnv} onValueChange={setSelectedEnv}>
              <SelectTrigger id="environment">
                <SelectValue placeholder="Select an environment" />
              </SelectTrigger>
              <SelectContent>
                {filteredEnvironments.map((env) => (
                  <SelectItem key={env.id} value={env.name}>
                    {env.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {selectedEnv && (
        <Card>
          <CardHeader>
            <CardTitle>Certificates in {selectedEnv}</CardTitle>
            <CardDescription>
              Showing {myCertificates.length} certificate(s) associated with your account.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {certsLoading ? (
              <div className="py-8 text-center text-muted-foreground">
                Loading certificates...
              </div>
            ) : myCertificates.length === 0 ? (
              <div className="py-8 text-center text-muted-foreground">
                No certificates found in this environment.
              </div>
            ) : (
              <CertificateTable
                certificates={myCertificates}
                envName={selectedEnv}
                showActions={false}
              />
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
