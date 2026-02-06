"use client";

import { useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { Plus, RefreshCw } from "lucide-react";
import { useAuth } from "@/hooks/use-auth";
import { useCertificates, useRevokeCertificate } from "@/hooks/use-certificates";
import { useToast } from "@/hooks/use-toast";
import { Button } from "@/components/ui/button";
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
import { CertificateTable } from "@/components/certificates/certificate-table";
import type { CertType } from "@/types/api";

export default function EnvironmentCertificatesPage() {
  const params = useParams();
  const envName = params.name as string;
  const { isOperator } = useAuth();
  const { toast } = useToast();

  const [certTypeFilter, setCertTypeFilter] = useState<CertType | "all">("all");
  const [includeExpired, setIncludeExpired] = useState(false);
  const [revokeSerial, setRevokeSerial] = useState<number | null>(null);
  const [revokeReason, setRevokeReason] = useState("");

  const {
    data: certData,
    isLoading,
    refetch,
  } = useCertificates(envName, {
    cert_type: certTypeFilter === "all" ? undefined : certTypeFilter,
    include_expired: includeExpired,
    include_revoked: true,
  });

  const revokeMutation = useRevokeCertificate(envName);

  const handleRevoke = async () => {
    if (revokeSerial === null) return;

    try {
      await revokeMutation.mutateAsync({
        serial: revokeSerial,
        data: revokeReason ? { reason: revokeReason } : undefined,
      });
      toast({
        title: "Certificate Revoked",
        description: `Certificate #${revokeSerial} has been revoked.`,
      });
      setRevokeSerial(null);
      setRevokeReason("");
    } catch (error) {
      toast({
        title: "Error",
        description: error instanceof Error ? error.message : "Failed to revoke certificate",
        variant: "destructive",
      });
    }
  };

  const certificates = certData?.certificates || [];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">
            Certificates - {envName}
          </h1>
          <p className="text-muted-foreground">
            Manage certificates issued in this environment.
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" />
            Refresh
          </Button>
          {isOperator && (
            <Button asChild>
              <Link href={`/admin/environments/${envName}/certificates/sign`}>
                <Plus className="mr-2 h-4 w-4" />
                Sign Certificate
              </Link>
            </Button>
          )}
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Filters</CardTitle>
        </CardHeader>
        <CardContent className="flex gap-4">
          <div className="w-48">
            <Label htmlFor="certType">Certificate Type</Label>
            <Select
              value={certTypeFilter}
              onValueChange={(v) => setCertTypeFilter(v as CertType | "all")}
            >
              <SelectTrigger id="certType">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Types</SelectItem>
                <SelectItem value="user">User</SelectItem>
                <SelectItem value="host">Host</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="flex items-end">
            <Button
              variant={includeExpired ? "default" : "outline"}
              onClick={() => setIncludeExpired(!includeExpired)}
            >
              {includeExpired ? "Hiding" : "Show"} Expired
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Issued Certificates</CardTitle>
          <CardDescription>
            Showing {certificates.length} certificate(s).
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="py-8 text-center text-muted-foreground">
              Loading certificates...
            </div>
          ) : certificates.length === 0 ? (
            <div className="py-8 text-center text-muted-foreground">
              No certificates found.
            </div>
          ) : (
            <CertificateTable
              certificates={certificates}
              envName={envName}
              showActions={isOperator}
              onRevoke={(serial) => setRevokeSerial(serial)}
            />
          )}
        </CardContent>
      </Card>

      <Dialog open={revokeSerial !== null} onOpenChange={() => setRevokeSerial(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Revoke Certificate</DialogTitle>
            <DialogDescription>
              Are you sure you want to revoke certificate #{revokeSerial}? This action
              cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2">
            <Label htmlFor="reason">Reason (optional)</Label>
            <Input
              id="reason"
              placeholder="Enter revocation reason"
              value={revokeReason}
              onChange={(e) => setRevokeReason(e.target.value)}
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRevokeSerial(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleRevoke}
              disabled={revokeMutation.isPending}
            >
              {revokeMutation.isPending ? "Revoking..." : "Revoke Certificate"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
