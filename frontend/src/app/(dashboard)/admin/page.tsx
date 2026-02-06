"use client";

import Link from "next/link";
import { Server, FileKey, Shield, Activity } from "lucide-react";
import { useEnvironments } from "@/hooks/use-environments";
import { useAuth } from "@/hooks/use-auth";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export default function AdminDashboardPage() {
  const { isAdmin } = useAuth();
  const { data: envData, isLoading } = useEnvironments();

  const environments = envData?.environments || [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Admin Dashboard</h1>
        <p className="text-muted-foreground">
          Overview of the SSH certificate management system.
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Environments</CardTitle>
            <Server className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {isLoading ? "-" : environments.length}
            </div>
            <p className="text-xs text-muted-foreground">
              Total configured environments
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Rotations</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {isLoading
                ? "-"
                : environments.filter((e) => e.has_old_user_ca || e.has_old_host_ca).length}
            </div>
            <p className="text-xs text-muted-foreground">
              CA rotations in grace period
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Certificates</CardTitle>
            <FileKey className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">-</div>
            <p className="text-xs text-muted-foreground">
              Total issued certificates
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">System Status</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">Healthy</div>
            <p className="text-xs text-muted-foreground">
              All services operational
            </p>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Recent Environments</CardTitle>
            <CardDescription>
              Quick access to recently updated environments.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <p className="text-sm text-muted-foreground">Loading...</p>
            ) : environments.length === 0 ? (
              <p className="text-sm text-muted-foreground">No environments configured.</p>
            ) : (
              <div className="space-y-2">
                {environments.slice(0, 5).map((env) => (
                  <Link
                    key={env.id}
                    href={`/admin/environments/${env.name}`}
                    className="flex items-center justify-between rounded-lg border p-3 hover:bg-accent transition-colors"
                  >
                    <div>
                      <p className="font-medium">{env.name}</p>
                      <p className="text-xs text-muted-foreground">
                        User CA: {env.user_ca_fingerprint.slice(0, 16)}...
                      </p>
                    </div>
                    {(env.has_old_user_ca || env.has_old_host_ca) && (
                      <span className="text-xs text-yellow-600 font-medium">
                        Rotating
                      </span>
                    )}
                  </Link>
                ))}
              </div>
            )}
            <Button asChild variant="link" className="mt-4 h-auto p-0">
              <Link href="/admin/environments">View all environments</Link>
            </Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Quick Actions</CardTitle>
            <CardDescription>
              Common administrative tasks.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            <Button asChild variant="outline" className="w-full justify-start">
              <Link href="/admin/environments">
                <Server className="mr-2 h-4 w-4" />
                Manage Environments
              </Link>
            </Button>
            {isAdmin && (
              <Button asChild variant="outline" className="w-full justify-start">
                <Link href="/admin/environments/new">
                  <Server className="mr-2 h-4 w-4" />
                  Create Environment
                </Link>
              </Button>
            )}
            <Button asChild variant="outline" className="w-full justify-start">
              <Link href="/admin/audit">
                <FileKey className="mr-2 h-4 w-4" />
                View Audit Logs
              </Link>
            </Button>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
