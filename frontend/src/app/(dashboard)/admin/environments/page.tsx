"use client";

import Link from "next/link";
import { Plus, Server } from "lucide-react";
import { useAuth } from "@/hooks/use-auth";
import { useEnvironments } from "@/hooks/use-environments";
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
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

export default function EnvironmentsPage() {
  const { isAdmin, accessibleEnvironments } = useAuth();
  const { data: envData, isLoading } = useEnvironments();

  const environments = envData?.environments || [];
  const filteredEnvironments = isAdmin
    ? environments
    : environments.filter((env) => accessibleEnvironments.includes(env.name));

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Environments</h1>
          <p className="text-muted-foreground">
            Manage SSH certificate environments and their CAs.
          </p>
        </div>
        {isAdmin && (
          <Button asChild>
            <Link href="/admin/environments/new">
              <Plus className="mr-2 h-4 w-4" />
              New Environment
            </Link>
          </Button>
        )}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>All Environments</CardTitle>
          <CardDescription>
            {filteredEnvironments.length} environment(s) available.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="py-8 text-center text-muted-foreground">
              Loading environments...
            </div>
          ) : filteredEnvironments.length === 0 ? (
            <div className="py-8 text-center text-muted-foreground">
              <Server className="mx-auto h-12 w-12 text-muted-foreground/50 mb-4" />
              <p>No environments available.</p>
              {isAdmin && (
                <Button asChild className="mt-4">
                  <Link href="/admin/environments/new">Create your first environment</Link>
                </Button>
              )}
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>User CA</TableHead>
                  <TableHead>Host CA</TableHead>
                  <TableHead>Default Validity</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredEnvironments.map((env) => (
                  <TableRow key={env.id}>
                    <TableCell>
                      <Link
                        href={`/admin/environments/${env.name}`}
                        className="font-medium hover:underline"
                      >
                        {env.name}
                      </Link>
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {env.user_ca_fingerprint.slice(0, 20)}...
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {env.host_ca_fingerprint.slice(0, 20)}...
                    </TableCell>
                    <TableCell>
                      <div className="text-sm">
                        <span className="text-muted-foreground">User:</span>{" "}
                        {env.default_user_cert_validity}
                      </div>
                      <div className="text-sm">
                        <span className="text-muted-foreground">Host:</span>{" "}
                        {env.default_host_cert_validity}
                      </div>
                    </TableCell>
                    <TableCell>
                      {env.has_old_user_ca || env.has_old_host_ca ? (
                        <Badge variant="warning">Rotating</Badge>
                      ) : (
                        <Badge variant="success">Active</Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-sm">
                      {formatDate(env.created_at)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
