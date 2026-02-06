"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ChevronRight, Home } from "lucide-react";
import { cn } from "@/lib/utils";

interface BreadcrumbItem {
  label: string;
  href?: string;
}

const pathLabels: Record<string, string> = {
  user: "User",
  admin: "Admin",
  config: "Configuration",
  certificates: "Certificates",
  environments: "Environments",
  request: "Request Certificate",
  new: "New",
  audit: "Audit Logs",
  users: "User Management",
  settings: "Settings",
  rotation: "CA Rotation",
  sign: "Sign Certificate",
};

function generateBreadcrumbs(pathname: string): BreadcrumbItem[] {
  const segments = pathname.split("/").filter(Boolean);
  const breadcrumbs: BreadcrumbItem[] = [];

  let currentPath = "";
  for (const segment of segments) {
    currentPath += `/${segment}`;

    // Check if segment is a dynamic route (starts with special characters or is UUID-like)
    const isDynamic = /^[a-f0-9-]{36}$/.test(segment) || /^\d+$/.test(segment);
    const label = isDynamic
      ? segment
      : pathLabels[segment] || segment.charAt(0).toUpperCase() + segment.slice(1);

    breadcrumbs.push({
      label,
      href: currentPath,
    });
  }

  // Last item shouldn't have a link
  if (breadcrumbs.length > 0) {
    breadcrumbs[breadcrumbs.length - 1].href = undefined;
  }

  return breadcrumbs;
}

export function Breadcrumbs() {
  const pathname = usePathname();
  const breadcrumbs = generateBreadcrumbs(pathname);

  if (breadcrumbs.length === 0) return null;

  return (
    <nav className="flex items-center space-x-1 text-sm text-muted-foreground">
      <Link
        href="/"
        className="flex items-center hover:text-foreground transition-colors"
      >
        <Home className="h-4 w-4" />
      </Link>
      {breadcrumbs.map((crumb, index) => (
        <span key={index} className="flex items-center">
          <ChevronRight className="h-4 w-4 mx-1" />
          {crumb.href ? (
            <Link
              href={crumb.href}
              className="hover:text-foreground transition-colors"
            >
              {crumb.label}
            </Link>
          ) : (
            <span className={cn("text-foreground")}>{crumb.label}</span>
          )}
        </span>
      ))}
    </nav>
  );
}
