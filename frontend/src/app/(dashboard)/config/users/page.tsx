"use client";

import { ExternalLink, Users, Shield, Key, Folder } from "lucide-react";
import { useAuth } from "@/hooks/use-auth";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export default function UserManagementPage() {
  const { isAdmin } = useAuth();

  // Get Keycloak URL from environment or use default
  const keycloakUrl = process.env.NEXT_PUBLIC_KEYCLOAK_URL || "http://localhost:8080";
  const keycloakRealm = process.env.NEXT_PUBLIC_KEYCLOAK_REALM || "sshmgr";
  const adminConsoleUrl = `${keycloakUrl}/admin/${keycloakRealm}/console`;

  if (!isAdmin) {
    return (
      <div className="flex items-center justify-center py-12">
        <Card className="max-w-md">
          <CardHeader>
            <CardTitle>Access Denied</CardTitle>
            <CardDescription>
              You need administrator permissions to manage users.
            </CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">User Management</h1>
        <p className="text-muted-foreground">
          Manage users, roles, and access through Keycloak.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Keycloak Admin Console</CardTitle>
          <CardDescription>
            User management is handled through the Keycloak identity provider.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-sm text-muted-foreground">
            Click the button below to open the Keycloak admin console where you can
            manage users, roles, and groups.
          </p>
          <Button asChild>
            <a href={adminConsoleUrl} target="_blank" rel="noopener noreferrer">
              <ExternalLink className="mr-2 h-4 w-4" />
              Open Keycloak Admin
            </a>
          </Button>
        </CardContent>
      </Card>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-lg">
              <Users className="h-5 w-5" />
              Users
            </CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">
            <p className="mb-2">Create and manage user accounts:</p>
            <ul className="list-disc list-inside space-y-1">
              <li>Create new users</li>
              <li>Reset passwords</li>
              <li>Enable/disable accounts</li>
              <li>View user sessions</li>
            </ul>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-lg">
              <Shield className="h-5 w-5" />
              Roles
            </CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">
            <p className="mb-2">sshmgr uses three realm roles:</p>
            <ul className="list-disc list-inside space-y-1">
              <li><strong>admin</strong> - Full system access</li>
              <li><strong>operator</strong> - Sign/revoke certificates</li>
              <li><strong>viewer</strong> - Read-only access</li>
            </ul>
            <p className="mt-2 text-xs">
              Assign roles to users in Keycloak &gt; Users &gt; Role Mapping
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-lg">
              <Folder className="h-5 w-5" />
              Groups
            </CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">
            <p className="mb-2">Environment access via groups:</p>
            <ul className="list-disc list-inside space-y-1">
              <li><code>/environments/prod</code></li>
              <li><code>/environments/staging</code></li>
              <li><code>/environments/dev</code></li>
            </ul>
            <p className="mt-2 text-xs">
              Add users to groups for environment access. Admins bypass group checks.
            </p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Quick Reference</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b">
                  <th className="text-left py-2 pr-4">Role</th>
                  <th className="text-left py-2 pr-4">View Environments</th>
                  <th className="text-left py-2 pr-4">Sign Certificates</th>
                  <th className="text-left py-2 pr-4">Revoke Certificates</th>
                  <th className="text-left py-2 pr-4">Create Environments</th>
                  <th className="text-left py-2">Rotate CAs</th>
                </tr>
              </thead>
              <tbody>
                <tr className="border-b">
                  <td className="py-2 pr-4 font-medium">Viewer</td>
                  <td className="py-2 pr-4 text-green-600">Yes*</td>
                  <td className="py-2 pr-4 text-red-600">No</td>
                  <td className="py-2 pr-4 text-red-600">No</td>
                  <td className="py-2 pr-4 text-red-600">No</td>
                  <td className="py-2 text-red-600">No</td>
                </tr>
                <tr className="border-b">
                  <td className="py-2 pr-4 font-medium">Operator</td>
                  <td className="py-2 pr-4 text-green-600">Yes*</td>
                  <td className="py-2 pr-4 text-green-600">Yes*</td>
                  <td className="py-2 pr-4 text-green-600">Yes*</td>
                  <td className="py-2 pr-4 text-red-600">No</td>
                  <td className="py-2 text-red-600">No</td>
                </tr>
                <tr>
                  <td className="py-2 pr-4 font-medium">Admin</td>
                  <td className="py-2 pr-4 text-green-600">All</td>
                  <td className="py-2 pr-4 text-green-600">All</td>
                  <td className="py-2 pr-4 text-green-600">All</td>
                  <td className="py-2 pr-4 text-green-600">Yes</td>
                  <td className="py-2 text-green-600">Yes</td>
                </tr>
              </tbody>
            </table>
          </div>
          <p className="text-xs text-muted-foreground mt-2">
            * Limited to environments the user has group membership for
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
