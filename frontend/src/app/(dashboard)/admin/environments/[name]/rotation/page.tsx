"use client";

import { useState } from "react";
import { useParams } from "next/navigation";
import { useAuth } from "@/hooks/use-auth";
import {
  useRotationStatus,
  useRotateCA,
  useCAPublicKey,
} from "@/hooks/use-environments";
import { useToast } from "@/hooks/use-toast";
import { formatDate, formatRelativeTime } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Label } from "@/components/ui/label";
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
  DialogTrigger,
} from "@/components/ui/dialog";
import { RotateCcw, AlertTriangle, CheckCircle } from "lucide-react";
import type { CertType, KeyType } from "@/types/api";

export default function CARotationPage() {
  const params = useParams();
  const envName = params.name as string;
  const { isAdmin } = useAuth();
  const { toast } = useToast();

  const { data: rotationStatus, isLoading } = useRotationStatus(envName);
  const { data: userCA } = useCAPublicKey(envName, "user", true);
  const { data: hostCA } = useCAPublicKey(envName, "host", true);
  const rotateMutation = useRotateCA(envName);

  const [rotateType, setRotateType] = useState<CertType>("user");
  const [gracePeriod, setGracePeriod] = useState("24h");
  const [keyType, setKeyType] = useState<KeyType>("ed25519");
  const [dialogOpen, setDialogOpen] = useState(false);

  if (!isAdmin) {
    return (
      <div className="flex items-center justify-center py-12">
        <Card className="max-w-md">
          <CardHeader>
            <CardTitle>Access Denied</CardTitle>
            <CardDescription>
              You need administrator permissions to rotate CAs.
            </CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }

  const handleRotate = async () => {
    try {
      await rotateMutation.mutateAsync({
        ca_type: rotateType,
        grace_period: gracePeriod,
        key_type: keyType,
      });
      toast({
        title: "CA Rotation Started",
        description: `${rotateType.toUpperCase()} CA rotation initiated with ${gracePeriod} grace period.`,
      });
      setDialogOpen(false);
    } catch (error) {
      toast({
        title: "Error",
        description: error instanceof Error ? error.message : "Failed to rotate CA",
        variant: "destructive",
      });
    }
  };

  const renderCAStatus = (
    type: "user" | "host",
    caStatus: typeof rotationStatus?.user_ca,
    caData: typeof userCA
  ) => {
    const isRotating = caStatus?.rotating;

    return (
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="capitalize">{type} CA</CardTitle>
            {isRotating ? (
              <Badge variant="warning">
                <RotateCcw className="mr-1 h-3 w-3 animate-spin" />
                Rotating
              </Badge>
            ) : (
              <Badge variant="success">
                <CheckCircle className="mr-1 h-3 w-3" />
                Stable
              </Badge>
            )}
          </div>
          <CardDescription>
            {type === "user"
              ? "Signs user certificates. Deploy to SSH servers."
              : "Signs host certificates. Deploy to SSH clients."}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <p className="text-sm font-medium text-muted-foreground">Current Fingerprint</p>
            <code className="text-xs bg-muted p-2 rounded block break-all mt-1">
              {caStatus?.fingerprint || "Loading..."}
            </code>
          </div>

          {isRotating && caStatus?.old_fingerprint && (
            <div className="rounded-lg border border-yellow-500 bg-yellow-50 p-4">
              <div className="flex items-start gap-2">
                <AlertTriangle className="h-5 w-5 text-yellow-600 mt-0.5" />
                <div>
                  <p className="font-medium text-yellow-800">Grace Period Active</p>
                  <p className="text-sm text-yellow-700 mt-1">
                    Old CA still valid until{" "}
                    {caStatus.old_expires_at
                      ? formatDate(caStatus.old_expires_at)
                      : "unknown"}
                    {" "}({caStatus.old_expires_at && formatRelativeTime(caStatus.old_expires_at)})
                  </p>
                  <p className="text-xs text-yellow-600 mt-2">
                    Old fingerprint: {caStatus.old_fingerprint}
                  </p>
                </div>
              </div>
            </div>
          )}

          {!isRotating && (
            <Dialog>
              <DialogTrigger asChild>
                <Button
                  variant="outline"
                  onClick={() => {
                    setRotateType(type);
                    setDialogOpen(true);
                  }}
                >
                  <RotateCcw className="mr-2 h-4 w-4" />
                  Rotate {type.toUpperCase()} CA
                </Button>
              </DialogTrigger>
            </Dialog>
          )}
        </CardContent>
      </Card>
    );
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">
          CA Rotation - {envName}
        </h1>
        <p className="text-muted-foreground">
          Rotate Certificate Authority keys with a grace period for migration.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>About CA Rotation</CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground space-y-2">
          <p>
            CA rotation generates a new keypair while keeping the old CA valid during a
            grace period. This allows for seamless migration without disrupting existing
            certificates.
          </p>
          <p>
            <strong>During the grace period:</strong>
          </p>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>New certificates are signed with the new CA</li>
            <li>Existing certificates signed by the old CA remain valid</li>
            <li>Deploy both CAs to servers/clients for compatibility</li>
          </ul>
          <p>
            After the grace period expires, the old CA is automatically removed and only
            the new CA will be used.
          </p>
        </CardContent>
      </Card>

      {isLoading ? (
        <p className="text-muted-foreground">Loading rotation status...</p>
      ) : (
        <div className="grid gap-4 md:grid-cols-2">
          {renderCAStatus("user", rotationStatus?.user_ca, userCA)}
          {renderCAStatus("host", rotationStatus?.host_ca, hostCA)}
        </div>
      )}

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Rotate {rotateType.toUpperCase()} CA</DialogTitle>
            <DialogDescription>
              This will generate a new {rotateType.toUpperCase()} CA keypair. The old CA will
              remain valid during the grace period.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
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
            </div>
            <div className="space-y-2">
              <Label htmlFor="gracePeriod">Grace Period</Label>
              <Select value={gracePeriod} onValueChange={setGracePeriod}>
                <SelectTrigger id="gracePeriod">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="1h">1 hour</SelectItem>
                  <SelectItem value="6h">6 hours</SelectItem>
                  <SelectItem value="12h">12 hours</SelectItem>
                  <SelectItem value="24h">24 hours</SelectItem>
                  <SelectItem value="48h">48 hours</SelectItem>
                  <SelectItem value="7d">7 days</SelectItem>
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                How long the old CA remains valid after rotation.
              </p>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDialogOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleRotate} disabled={rotateMutation.isPending}>
              {rotateMutation.isPending ? "Rotating..." : "Start Rotation"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
