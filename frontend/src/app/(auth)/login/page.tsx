"use client";

import { signIn } from "next-auth/react";
import { useSearchParams } from "next/navigation";
import { Key, Shield } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export default function LoginPage() {
  const searchParams = useSearchParams();
  const error = searchParams.get("error");
  const callbackUrl = searchParams.get("callbackUrl") || "/user";

  const handleLogin = () => {
    signIn("keycloak", { callbackUrl });
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-slate-100 to-slate-200">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-primary">
            <Key className="h-8 w-8 text-primary-foreground" />
          </div>
          <CardTitle className="text-2xl">sshmgr</CardTitle>
          <CardDescription>
            SSH Certificate Management System
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {error && (
            <div className="rounded-md bg-destructive/10 p-3 text-sm text-destructive">
              {error === "OAuthSignin" && "Error starting sign in process."}
              {error === "OAuthCallback" && "Error during authentication callback."}
              {error === "OAuthAccountNotLinked" && "Account not linked."}
              {error === "Callback" && "Authentication callback error."}
              {error === "AccessDenied" && "Access denied."}
              {!["OAuthSignin", "OAuthCallback", "OAuthAccountNotLinked", "Callback", "AccessDenied"].includes(error) &&
                "An error occurred during sign in."}
            </div>
          )}

          <Button onClick={handleLogin} className="w-full" size="lg">
            <Shield className="mr-2 h-5 w-5" />
            Sign in with Keycloak
          </Button>

          <p className="text-center text-xs text-muted-foreground">
            Sign in to manage SSH certificates and environments.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
