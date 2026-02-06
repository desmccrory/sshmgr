"use client";

import { useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { useAuth } from "@/hooks/use-auth";
import { useEnvironment } from "@/hooks/use-environments";
import {
  useSignUserCertificate,
  useSignHostCertificate,
} from "@/hooks/use-certificates";
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
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";
import { Copy, Check } from "lucide-react";
import type { CertType } from "@/types/api";

export default function SignCertificatePage() {
  const params = useParams();
  const router = useRouter();
  const envName = params.name as string;
  const { isOperator, user } = useAuth();
  const { toast } = useToast();
  const { data: env } = useEnvironment(envName);

  const [certType, setCertType] = useState<CertType>("user");
  const [publicKey, setPublicKey] = useState("");
  const [principals, setPrincipals] = useState("");
  const [keyId, setKeyId] = useState(user?.email || "");
  const [validity, setValidity] = useState("");
  const [forceCommand, setForceCommand] = useState("");
  const [signedCert, setSignedCert] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const signUserMutation = useSignUserCertificate(envName);
  const signHostMutation = useSignHostCertificate(envName);

  if (!isOperator) {
    return (
      <div className="flex items-center justify-center py-12">
        <Card className="max-w-md">
          <CardHeader>
            <CardTitle>Access Denied</CardTitle>
            <CardDescription>
              You need operator permissions to sign certificates.
            </CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!publicKey || !principals) {
      toast({
        title: "Validation Error",
        description: "Public key and principals are required.",
        variant: "destructive",
      });
      return;
    }

    const principalList = principals.split(",").map((p) => p.trim()).filter(Boolean);

    try {
      let result;
      if (certType === "user") {
        if (!keyId) {
          toast({
            title: "Validation Error",
            description: "Key ID is required for user certificates.",
            variant: "destructive",
          });
          return;
        }
        result = await signUserMutation.mutateAsync({
          public_key: publicKey.trim(),
          principals: principalList,
          key_id: keyId,
          validity: validity || undefined,
          force_command: forceCommand || undefined,
        });
      } else {
        result = await signHostMutation.mutateAsync({
          public_key: publicKey.trim(),
          principals: principalList,
          validity: validity || undefined,
        });
      }

      setSignedCert(result.certificate || null);
      toast({
        title: "Certificate Signed",
        description: `${certType.toUpperCase()} certificate #${result.serial} has been issued.`,
      });
    } catch (error) {
      toast({
        title: "Error",
        description: error instanceof Error ? error.message : "Failed to sign certificate",
        variant: "destructive",
      });
    }
  };

  const handleCopy = async () => {
    if (signedCert) {
      await navigator.clipboard.writeText(signedCert);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const resetForm = () => {
    setSignedCert(null);
    setPublicKey("");
    setPrincipals("");
    setKeyId(user?.email || "");
    setValidity("");
    setForceCommand("");
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">
          Sign Certificate - {envName}
        </h1>
        <p className="text-muted-foreground">
          Sign a new SSH certificate using the environment CA.
        </p>
      </div>

      {signedCert ? (
        <Card>
          <CardHeader>
            <CardTitle>Certificate Issued</CardTitle>
            <CardDescription>
              The certificate has been signed successfully.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="relative">
              <Textarea
                value={signedCert}
                readOnly
                className="font-mono text-xs h-32"
              />
              <Button
                variant="outline"
                size="sm"
                className="absolute right-2 top-2"
                onClick={handleCopy}
              >
                {copied ? (
                  <Check className="h-4 w-4" />
                ) : (
                  <Copy className="h-4 w-4" />
                )}
              </Button>
            </div>
            <div className="flex gap-2">
              <Button onClick={resetForm}>Sign Another</Button>
              <Button
                variant="outline"
                onClick={() => router.push(`/admin/environments/${envName}/certificates`)}
              >
                View All Certificates
              </Button>
            </div>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardHeader>
            <CardTitle>Certificate Details</CardTitle>
          </CardHeader>
          <CardContent>
            <Tabs value={certType} onValueChange={(v) => setCertType(v as CertType)}>
              <TabsList className="mb-4">
                <TabsTrigger value="user">User Certificate</TabsTrigger>
                <TabsTrigger value="host">Host Certificate</TabsTrigger>
              </TabsList>

              <form onSubmit={handleSubmit} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="publicKey">SSH Public Key *</Label>
                  <Textarea
                    id="publicKey"
                    placeholder="ssh-ed25519 AAAA... user@host"
                    value={publicKey}
                    onChange={(e) => setPublicKey(e.target.value)}
                    className="font-mono text-sm"
                    rows={3}
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="principals">
                    {certType === "user" ? "Principals (usernames) *" : "Principals (hostnames/IPs) *"}
                  </Label>
                  <Input
                    id="principals"
                    placeholder={
                      certType === "user"
                        ? "admin, deploy, ci-service"
                        : "server1.example.com, 10.0.0.5"
                    }
                    value={principals}
                    onChange={(e) => setPrincipals(e.target.value)}
                  />
                  <p className="text-xs text-muted-foreground">
                    Comma-separated list
                  </p>
                </div>

                {certType === "user" && (
                  <div className="space-y-2">
                    <Label htmlFor="keyId">Key ID *</Label>
                    <Input
                      id="keyId"
                      placeholder="user@example.com"
                      value={keyId}
                      onChange={(e) => setKeyId(e.target.value)}
                    />
                    <p className="text-xs text-muted-foreground">
                      Identifier for audit trail (typically email)
                    </p>
                  </div>
                )}

                <div className="space-y-2">
                  <Label htmlFor="validity">Validity Period</Label>
                  <Select value={validity} onValueChange={setValidity}>
                    <SelectTrigger id="validity">
                      <SelectValue placeholder={`Default (${certType === "user" ? env?.default_user_cert_validity : env?.default_host_cert_validity})`} />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="">Use Default</SelectItem>
                      {certType === "user" ? (
                        <>
                          <SelectItem value="1h">1 hour</SelectItem>
                          <SelectItem value="4h">4 hours</SelectItem>
                          <SelectItem value="8h">8 hours</SelectItem>
                          <SelectItem value="12h">12 hours</SelectItem>
                          <SelectItem value="24h">24 hours</SelectItem>
                        </>
                      ) : (
                        <>
                          <SelectItem value="30d">30 days</SelectItem>
                          <SelectItem value="90d">90 days</SelectItem>
                          <SelectItem value="180d">180 days</SelectItem>
                          <SelectItem value="365d">365 days</SelectItem>
                        </>
                      )}
                    </SelectContent>
                  </Select>
                </div>

                {certType === "user" && (
                  <div className="space-y-2">
                    <Label htmlFor="forceCommand">Force Command (optional)</Label>
                    <Input
                      id="forceCommand"
                      placeholder="/usr/bin/rsync --server"
                      value={forceCommand}
                      onChange={(e) => setForceCommand(e.target.value)}
                    />
                    <p className="text-xs text-muted-foreground">
                      Restrict certificate to execute only this command
                    </p>
                  </div>
                )}

                <Button
                  type="submit"
                  disabled={signUserMutation.isPending || signHostMutation.isPending}
                >
                  {signUserMutation.isPending || signHostMutation.isPending
                    ? "Signing..."
                    : "Sign Certificate"}
                </Button>
              </form>
            </Tabs>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
