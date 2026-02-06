"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/hooks/use-auth";
import { useEnvironments } from "@/hooks/use-environments";
import { useSignUserCertificate } from "@/hooks/use-certificates";
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
import { Copy, Check } from "lucide-react";

export default function RequestCertificatePage() {
  const router = useRouter();
  const { user, accessibleEnvironments, isAdmin, isOperator } = useAuth();
  const { toast } = useToast();
  const { data: envData } = useEnvironments();

  const [selectedEnv, setSelectedEnv] = useState<string>("");
  const [publicKey, setPublicKey] = useState("");
  const [principals, setPrincipals] = useState(user?.email || "");
  const [validity, setValidity] = useState("8h");
  const [signedCert, setSignedCert] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const signMutation = useSignUserCertificate(selectedEnv);

  const environments = envData?.environments || [];
  const filteredEnvironments = isAdmin
    ? environments
    : environments.filter((env) => accessibleEnvironments.includes(env.name));

  if (!isOperator) {
    return (
      <div className="flex items-center justify-center py-12">
        <Card className="max-w-md">
          <CardHeader>
            <CardTitle>Access Denied</CardTitle>
            <CardDescription>
              You need operator permissions to request certificates.
            </CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!selectedEnv || !publicKey || !principals) {
      toast({
        title: "Validation Error",
        description: "Please fill in all required fields.",
        variant: "destructive",
      });
      return;
    }

    try {
      const result = await signMutation.mutateAsync({
        public_key: publicKey.trim(),
        principals: principals.split(",").map((p) => p.trim()),
        key_id: user?.email || "unknown",
        validity,
      });

      setSignedCert(result.certificate || null);
      toast({
        title: "Certificate Signed",
        description: `Certificate #${result.serial} has been issued.`,
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

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Request Certificate</h1>
        <p className="text-muted-foreground">
          Request a new SSH user certificate for authentication.
        </p>
      </div>

      {signedCert ? (
        <Card>
          <CardHeader>
            <CardTitle>Certificate Issued</CardTitle>
            <CardDescription>
              Your certificate has been signed. Copy it and save it alongside your private key.
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
            <p className="text-sm text-muted-foreground">
              Save this certificate as <code>id_ed25519-cert.pub</code> (or similar) in your
              <code>~/.ssh</code> directory.
            </p>
            <Button onClick={() => setSignedCert(null)}>
              Request Another
            </Button>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardHeader>
            <CardTitle>Certificate Request</CardTitle>
            <CardDescription>
              Provide your SSH public key to receive a signed certificate.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="environment">Environment *</Label>
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
                <p className="text-xs text-muted-foreground">
                  Paste your public key (e.g., contents of ~/.ssh/id_ed25519.pub)
                </p>
              </div>

              <div className="space-y-2">
                <Label htmlFor="principals">Principals *</Label>
                <Input
                  id="principals"
                  placeholder="username"
                  value={principals}
                  onChange={(e) => setPrincipals(e.target.value)}
                />
                <p className="text-xs text-muted-foreground">
                  Comma-separated list of usernames this certificate authorizes
                </p>
              </div>

              <div className="space-y-2">
                <Label htmlFor="validity">Validity Period</Label>
                <Select value={validity} onValueChange={setValidity}>
                  <SelectTrigger id="validity">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="1h">1 hour</SelectItem>
                    <SelectItem value="4h">4 hours</SelectItem>
                    <SelectItem value="8h">8 hours (default)</SelectItem>
                    <SelectItem value="12h">12 hours</SelectItem>
                    <SelectItem value="24h">24 hours</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <Button type="submit" disabled={signMutation.isPending}>
                {signMutation.isPending ? "Signing..." : "Request Certificate"}
              </Button>
            </form>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
