"use client";

import { useState } from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { Trash2, RotateCcw, FileKey, Copy, Check, Key } from "lucide-react";
import { useAuth } from "@/hooks/use-auth";
import {
  useEnvironment,
  useDeleteEnvironment,
  useCAPublicKey,
  useRotationStatus,
} from "@/hooks/use-environments";
import { useToast } from "@/hooks/use-toast";
import { formatDate } from "@/lib/utils";
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
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";

export default function EnvironmentDetailPage() {
  const params = useParams();
  const router = useRouter();
  const envName = params.name as string;
  const { isAdmin, isOperator } = useAuth();
  const { toast } = useToast();

  const { data: env, isLoading } = useEnvironment(envName);
  const { data: userCA } = useCAPublicKey(envName, "user", true);
  const { data: hostCA } = useCAPublicKey(envName, "host", true);
  const { data: rotationStatus } = useRotationStatus(envName);
  const deleteMutation = useDeleteEnvironment();

  const [deleteOpen, setDeleteOpen] = useState(false);
  const [copiedCA, setCopiedCA] = useState<string | null>(null);

  const handleDelete = async () => {
    try {
      await deleteMutation.mutateAsync(envName);
      toast({
        title: "Environment Deleted",
        description: `Environment "${envName}" has been deleted.`,
      });
      router.push("/admin/environments");
    } catch (error) {
      toast({
        title: "Error",
        description: error instanceof Error ? error.message : "Failed to delete environment",
        variant: "destructive",
      });
    }
    setDeleteOpen(false);
  };

  const copyToClipboard = async (text: string, label: string) => {
    await navigator.clipboard.writeText(text);
    setCopiedCA(label);
    setTimeout(() => setCopiedCA(null), 2000);
    toast({
      title: "Copied",
      description: `${label} copied to clipboard.`,
    });
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <p className="text-muted-foreground">Loading environment...</p>
      </div>
    );
  }

  if (!env) {
    return (
      <div className="flex items-center justify-center py-12">
        <Card className="max-w-md">
          <CardHeader>
            <CardTitle>Environment Not Found</CardTitle>
            <CardDescription>
              The environment "{envName}" does not exist.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Button asChild>
              <Link href="/admin/environments">Back to Environments</Link>
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{env.name}</h1>
          <p className="text-muted-foreground">
            Environment configuration and CA management.
          </p>
        </div>
        <div className="flex gap-2">
          {isOperator && (
            <Button asChild>
              <Link href={`/admin/environments/${envName}/certificates`}>
                <FileKey className="mr-2 h-4 w-4" />
                Certificates
              </Link>
            </Button>
          )}
          {isAdmin && (
            <>
              <Button asChild variant="outline">
                <Link href={`/admin/environments/${envName}/rotation`}>
                  <RotateCcw className="mr-2 h-4 w-4" />
                  CA Rotation
                </Link>
              </Button>
              <Dialog open={deleteOpen} onOpenChange={setDeleteOpen}>
                <DialogTrigger asChild>
                  <Button variant="destructive">
                    <Trash2 className="mr-2 h-4 w-4" />
                    Delete
                  </Button>
                </DialogTrigger>
                <DialogContent>
                  <DialogHeader>
                    <DialogTitle>Delete Environment</DialogTitle>
                    <DialogDescription>
                      Are you sure you want to delete "{envName}"? This will permanently
                      delete the environment and all associated certificates. This action
                      cannot be undone.
                    </DialogDescription>
                  </DialogHeader>
                  <DialogFooter>
                    <Button variant="outline" onClick={() => setDeleteOpen(false)}>
                      Cancel
                    </Button>
                    <Button
                      variant="destructive"
                      onClick={handleDelete}
                      disabled={deleteMutation.isPending}
                    >
                      {deleteMutation.isPending ? "Deleting..." : "Delete Environment"}
                    </Button>
                  </DialogFooter>
                </DialogContent>
              </Dialog>
            </>
          )}
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Key className="h-5 w-5" />
              User CA
            </CardTitle>
            <CardDescription>
              Signs user certificates. Deploy to SSH servers.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <p className="text-sm font-medium mb-1">Fingerprint</p>
              <code className="text-xs bg-muted p-2 rounded block break-all">
                {env.user_ca_fingerprint}
              </code>
            </div>
            {userCA && (
              <div>
                <div className="flex items-center justify-between mb-1">
                  <p className="text-sm font-medium">Public Key</p>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => copyToClipboard(userCA.public_key, "User CA")}
                  >
                    {copiedCA === "User CA" ? (
                      <Check className="h-4 w-4" />
                    ) : (
                      <Copy className="h-4 w-4" />
                    )}
                  </Button>
                </div>
                <Textarea
                  value={userCA.public_key}
                  readOnly
                  className="font-mono text-xs h-20"
                />
              </div>
            )}
            {rotationStatus?.user_ca.rotating && (
              <Badge variant="warning">Rotation in Progress</Badge>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Key className="h-5 w-5" />
              Host CA
            </CardTitle>
            <CardDescription>
              Signs host certificates. Deploy to SSH clients.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <p className="text-sm font-medium mb-1">Fingerprint</p>
              <code className="text-xs bg-muted p-2 rounded block break-all">
                {env.host_ca_fingerprint}
              </code>
            </div>
            {hostCA && (
              <div>
                <div className="flex items-center justify-between mb-1">
                  <p className="text-sm font-medium">Public Key</p>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => copyToClipboard(hostCA.public_key, "Host CA")}
                  >
                    {copiedCA === "Host CA" ? (
                      <Check className="h-4 w-4" />
                    ) : (
                      <Copy className="h-4 w-4" />
                    )}
                  </Button>
                </div>
                <Textarea
                  value={hostCA.public_key}
                  readOnly
                  className="font-mono text-xs h-20"
                />
              </div>
            )}
            {rotationStatus?.host_ca.rotating && (
              <Badge variant="warning">Rotation in Progress</Badge>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Environment Details</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="grid gap-4 md:grid-cols-2">
            <div>
              <dt className="text-sm font-medium text-muted-foreground">Created</dt>
              <dd>{formatDate(env.created_at)}</dd>
            </div>
            <div>
              <dt className="text-sm font-medium text-muted-foreground">Last Updated</dt>
              <dd>{env.updated_at ? formatDate(env.updated_at) : "Never"}</dd>
            </div>
            <div>
              <dt className="text-sm font-medium text-muted-foreground">Default User Cert Validity</dt>
              <dd>{env.default_user_cert_validity}</dd>
            </div>
            <div>
              <dt className="text-sm font-medium text-muted-foreground">Default Host Cert Validity</dt>
              <dd>{env.default_host_cert_validity}</dd>
            </div>
          </dl>
        </CardContent>
      </Card>
    </div>
  );
}
