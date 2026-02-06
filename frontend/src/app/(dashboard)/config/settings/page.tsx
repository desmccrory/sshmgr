"use client";

import { useAuth } from "@/hooks/use-auth";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

export default function SystemSettingsPage() {
  const { isAdmin } = useAuth();

  if (!isAdmin) {
    return (
      <div className="flex items-center justify-center py-12">
        <Card className="max-w-md">
          <CardHeader>
            <CardTitle>Access Denied</CardTitle>
            <CardDescription>
              You need administrator permissions to view settings.
            </CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }

  // These would typically come from an API endpoint
  const settings = [
    {
      category: "API",
      items: [
        { name: "API URL", value: process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000", sensitive: false },
        { name: "API Version", value: "v1", sensitive: false },
      ],
    },
    {
      category: "Authentication",
      items: [
        { name: "Keycloak URL", value: process.env.NEXT_PUBLIC_KEYCLOAK_URL || "http://localhost:8080", sensitive: false },
        { name: "Realm", value: process.env.NEXT_PUBLIC_KEYCLOAK_REALM || "sshmgr", sensitive: false },
        { name: "Client ID", value: "sshmgr-web", sensitive: false },
      ],
    },
    {
      category: "Default Certificate Validity",
      items: [
        { name: "User Certificates", value: "8 hours", sensitive: false },
        { name: "Host Certificates", value: "90 days", sensitive: false },
      ],
    },
    {
      category: "Security",
      items: [
        { name: "Master Key", value: "********", sensitive: true },
        { name: "Rate Limiting", value: "Enabled", sensitive: false },
        { name: "CORS Origins", value: process.env.NEXT_PUBLIC_APP_URL || "Not configured", sensitive: false },
      ],
    },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">System Settings</h1>
        <p className="text-muted-foreground">
          Current system configuration (read-only).
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Configuration Overview</CardTitle>
          <CardDescription>
            These settings are configured via environment variables and cannot be
            changed through the UI.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground mb-4">
            To modify these settings, update the environment variables in your
            deployment configuration (.env file or container environment).
          </p>
        </CardContent>
      </Card>

      {settings.map((section) => (
        <Card key={section.category}>
          <CardHeader>
            <CardTitle className="text-lg">{section.category}</CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Setting</TableHead>
                  <TableHead>Value</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {section.items.map((item) => (
                  <TableRow key={item.name}>
                    <TableCell className="font-medium">{item.name}</TableCell>
                    <TableCell>
                      {item.sensitive ? (
                        <Badge variant="secondary">Hidden</Badge>
                      ) : (
                        <code className="text-sm bg-muted px-2 py-1 rounded">
                          {item.value}
                        </code>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      ))}

      <Card>
        <CardHeader>
          <CardTitle>Environment Variables Reference</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-sm text-muted-foreground space-y-4">
            <div>
              <h4 className="font-medium text-foreground">Backend API</h4>
              <ul className="list-disc list-inside mt-1 space-y-1">
                <li><code>SSHMGR_DATABASE_URL</code> - PostgreSQL connection string</li>
                <li><code>SSHMGR_MASTER_KEY</code> - Fernet encryption key for CA private keys</li>
                <li><code>SSHMGR_API_HOST</code> / <code>SSHMGR_API_PORT</code> - API server binding</li>
              </ul>
            </div>
            <div>
              <h4 className="font-medium text-foreground">Keycloak</h4>
              <ul className="list-disc list-inside mt-1 space-y-1">
                <li><code>SSHMGR_KEYCLOAK_URL</code> - Keycloak server URL</li>
                <li><code>SSHMGR_KEYCLOAK_REALM</code> - Keycloak realm name</li>
                <li><code>SSHMGR_KEYCLOAK_CLIENT_ID</code> - OAuth client ID for API</li>
                <li><code>SSHMGR_KEYCLOAK_CLIENT_SECRET</code> - OAuth client secret</li>
              </ul>
            </div>
            <div>
              <h4 className="font-medium text-foreground">Frontend</h4>
              <ul className="list-disc list-inside mt-1 space-y-1">
                <li><code>NEXT_PUBLIC_API_URL</code> - Backend API URL</li>
                <li><code>KEYCLOAK_URL</code> / <code>KEYCLOAK_REALM</code> - Keycloak config</li>
                <li><code>AUTH_SECRET</code> - Auth.js session encryption key</li>
              </ul>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
