"use client";

import { useState } from "react";
import { useAuth } from "@/hooks/use-auth";
import { useEnvironments } from "@/hooks/use-environments";
import { useCertificates } from "@/hooks/use-certificates";
import { formatDate } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { FileKey, Ban } from "lucide-react";

export default function AuditLogsPage() {
  const { isAdmin, accessibleEnvironments } = useAuth();
  const { data: envData } = useEnvironments();
  const [selectedEnv, setSelectedEnv] = useState<string>("");

  const { data: certData, isLoading } = useCertificates(selectedEnv, {
    include_expired: true,
    include_revoked: true,
    limit: 100,
  });

  const environments = envData?.environments || [];
  const filteredEnvironments = isAdmin
    ? environments
    : environments.filter((env) => accessibleEnvironments.includes(env.name));

  // Convert certificates to audit events
  const auditEvents = (certData?.certificates || [])
    .flatMap((cert) => {
      const events = [
        {
          id: `${cert.id}-issued`,
          type: "issued" as const,
          serial: cert.serial,
          certType: cert.cert_type,
          keyId: cert.key_id,
          user: cert.issued_by,
          timestamp: cert.issued_at,
        },
      ];
      if (cert.revoked_at && cert.revoked_by) {
        events.push({
          id: `${cert.id}-revoked`,
          type: "revoked" as const,
          serial: cert.serial,
          certType: cert.cert_type,
          keyId: cert.key_id,
          user: cert.revoked_by,
          timestamp: cert.revoked_at,
          reason: cert.revocation_reason,
        });
      }
      return events;
    })
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Audit Logs</h1>
        <p className="text-muted-foreground">
          Certificate issuance and revocation history.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Filter</CardTitle>
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
            <CardTitle>Audit Trail - {selectedEnv}</CardTitle>
            <CardDescription>
              Showing {auditEvents.length} event(s).
            </CardDescription>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <div className="py-8 text-center text-muted-foreground">
                Loading audit logs...
              </div>
            ) : auditEvents.length === 0 ? (
              <div className="py-8 text-center text-muted-foreground">
                No audit events found.
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Timestamp</TableHead>
                    <TableHead>Action</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Serial</TableHead>
                    <TableHead>Key ID</TableHead>
                    <TableHead>User</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {auditEvents.map((event) => (
                    <TableRow key={event.id}>
                      <TableCell className="text-sm">
                        {formatDate(event.timestamp)}
                      </TableCell>
                      <TableCell>
                        {event.type === "issued" ? (
                          <Badge variant="success" className="gap-1">
                            <FileKey className="h-3 w-3" />
                            Issued
                          </Badge>
                        ) : (
                          <Badge variant="destructive" className="gap-1">
                            <Ban className="h-3 w-3" />
                            Revoked
                          </Badge>
                        )}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline">
                          {event.certType.toUpperCase()}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-mono">{event.serial}</TableCell>
                      <TableCell className="font-mono text-sm">
                        {event.keyId}
                      </TableCell>
                      <TableCell className="text-sm">{event.user}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
