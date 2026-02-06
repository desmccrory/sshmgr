"use client";

import { useSession } from "next-auth/react";

type Role = "admin" | "operator" | "viewer";

const ROLE_HIERARCHY: Record<Role, Role[]> = {
  admin: ["admin", "operator", "viewer"],
  operator: ["operator", "viewer"],
  viewer: ["viewer"],
};

export function useAuth() {
  const { data: session, status } = useSession();

  const hasRole = (role: Role): boolean => {
    if (!session?.user?.roles) return false;
    return session.user.roles.some((userRole) =>
      ROLE_HIERARCHY[userRole as Role]?.includes(role)
    );
  };

  const hasMinimumRole = (minimumRole: Role): boolean => {
    if (!session?.user?.roles) return false;
    // User has minimum role if any of their roles includes the minimum role in its hierarchy
    return session.user.roles.some((userRole) =>
      ROLE_HIERARCHY[userRole as Role]?.includes(minimumRole)
    );
  };

  const canAccessEnvironment = (envName: string): boolean => {
    if (!session?.user) return false;
    if (hasRole("admin")) return true;
    const envGroups = session.user.groups
      .filter((g) => g.startsWith("/environments/"))
      .map((g) => g.replace("/environments/", ""));
    return envGroups.includes(envName);
  };

  const accessibleEnvironments = session?.user?.groups
    ?.filter((g) => g.startsWith("/environments/"))
    .map((g) => g.replace("/environments/", "")) || [];

  return {
    session,
    status,
    isAuthenticated: status === "authenticated",
    isLoading: status === "loading",
    user: session?.user,
    accessToken: session?.accessToken,
    hasRole,
    hasMinimumRole,
    canAccessEnvironment,
    isAdmin: hasRole("admin"),
    isOperator: hasMinimumRole("operator"),
    isViewer: hasMinimumRole("viewer"),
    accessibleEnvironments,
  };
}
