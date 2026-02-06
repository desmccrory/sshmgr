"use client";

import Link from "next/link";
import { FileKey, Key, Server, Clock } from "lucide-react";
import { useAuth } from "@/hooks/use-auth";
import { useEnvironments } from "@/hooks/use-environments";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export default function UserDashboardPage() {
  const { user, isOperator, accessibleEnvironments } = useAuth();
  const { data: envData, isLoading } = useEnvironments();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Welcome, {user?.name || "User"}</h1>
        <p className="text-muted-foreground">
          Manage your SSH certificates and access environments.
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">My Certificates</CardTitle>
            <FileKey className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">-</div>
            <p className="text-xs text-muted-foreground">
              Active certificates issued to you
            </p>
            <Button asChild variant="link" className="mt-2 h-auto p-0">
              <Link href="/user/certificates">View certificates</Link>
            </Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Environments</CardTitle>
            <Server className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {isLoading ? "-" : accessibleEnvironments.length}
            </div>
            <p className="text-xs text-muted-foreground">
              Environments you can access
            </p>
            <Button asChild variant="link" className="mt-2 h-auto p-0">
              <Link href="/admin/environments">Browse environments</Link>
            </Button>
          </CardContent>
        </Card>

        {isOperator && (
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Request Certificate</CardTitle>
              <Key className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground mb-4">
                Request a new SSH user certificate for authentication.
              </p>
              <Button asChild>
                <Link href="/user/request">Request New</Link>
              </Button>
            </CardContent>
          </Card>
        )}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Quick Actions</CardTitle>
          <CardDescription>
            Common tasks you can perform
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4 md:grid-cols-2">
          <Button asChild variant="outline" className="justify-start">
            <Link href="/user/certificates">
              <FileKey className="mr-2 h-4 w-4" />
              View My Certificates
            </Link>
          </Button>
          {isOperator && (
            <Button asChild variant="outline" className="justify-start">
              <Link href="/user/request">
                <Key className="mr-2 h-4 w-4" />
                Request New Certificate
              </Link>
            </Button>
          )}
          <Button asChild variant="outline" className="justify-start">
            <Link href="/admin/environments">
              <Server className="mr-2 h-4 w-4" />
              Browse Environments
            </Link>
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
