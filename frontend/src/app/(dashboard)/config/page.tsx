"use client";

import Link from "next/link";
import { Users, Settings, ExternalLink } from "lucide-react";
import { useAuth } from "@/hooks/use-auth";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export default function ConfigurationPage() {
  const { isAdmin } = useAuth();

  if (!isAdmin) {
    return (
      <div className="flex items-center justify-center py-12">
        <Card className="max-w-md">
          <CardHeader>
            <CardTitle>Access Denied</CardTitle>
            <CardDescription>
              You need administrator permissions to access configuration.
            </CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Configuration</h1>
        <p className="text-muted-foreground">
          System configuration and user management.
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Users className="h-5 w-5" />
              User Management
            </CardTitle>
            <CardDescription>
              Manage users, roles, and environment access through Keycloak.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground mb-4">
              User authentication is managed through Keycloak. Use the Keycloak
              admin console to:
            </p>
            <ul className="text-sm text-muted-foreground list-disc list-inside mb-4 space-y-1">
              <li>Create and manage users</li>
              <li>Assign roles (admin, operator, viewer)</li>
              <li>Configure environment access groups</li>
              <li>Set up identity providers (LDAP, SAML, etc.)</li>
            </ul>
            <Button asChild>
              <Link href="/config/users">
                <Users className="mr-2 h-4 w-4" />
                User Management
              </Link>
            </Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Settings className="h-5 w-5" />
              System Settings
            </CardTitle>
            <CardDescription>
              View system configuration and environment variables.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground mb-4">
              View the current system configuration including API settings,
              authentication configuration, and default values.
            </p>
            <Button asChild variant="outline">
              <Link href="/config/settings">
                <Settings className="mr-2 h-4 w-4" />
                View Settings
              </Link>
            </Button>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
