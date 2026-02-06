"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Home,
  Key,
  Shield,
  Server,
  Settings,
  Users,
  FileKey,
  RotateCcw,
  ClipboardList,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useAuth } from "@/hooks/use-auth";
import { Separator } from "@/components/ui/separator";

interface NavItem {
  title: string;
  href: string;
  icon: React.ElementType;
  requiredRole?: "admin" | "operator" | "viewer";
}

const userNavItems: NavItem[] = [
  {
    title: "Dashboard",
    href: "/user",
    icon: Home,
  },
  {
    title: "My Certificates",
    href: "/user/certificates",
    icon: FileKey,
  },
  {
    title: "Request Certificate",
    href: "/user/request",
    icon: Key,
    requiredRole: "operator",
  },
];

const adminNavItems: NavItem[] = [
  {
    title: "Dashboard",
    href: "/admin",
    icon: Shield,
  },
  {
    title: "Environments",
    href: "/admin/environments",
    icon: Server,
  },
  {
    title: "Audit Logs",
    href: "/admin/audit",
    icon: ClipboardList,
  },
];

const configNavItems: NavItem[] = [
  {
    title: "User Management",
    href: "/config/users",
    icon: Users,
    requiredRole: "admin",
  },
  {
    title: "Settings",
    href: "/config/settings",
    icon: Settings,
    requiredRole: "admin",
  },
];

function NavSection({
  title,
  items,
}: {
  title: string;
  items: NavItem[];
}) {
  const pathname = usePathname();
  const { hasMinimumRole } = useAuth();

  const filteredItems = items.filter(
    (item) => !item.requiredRole || hasMinimumRole(item.requiredRole)
  );

  if (filteredItems.length === 0) return null;

  return (
    <div className="px-3 py-2">
      <h2 className="mb-2 px-4 text-lg font-semibold tracking-tight">{title}</h2>
      <div className="space-y-1">
        {filteredItems.map((item) => (
          <Link
            key={item.href}
            href={item.href}
            className={cn(
              "flex items-center rounded-lg px-4 py-2 text-sm font-medium transition-colors hover:bg-accent hover:text-accent-foreground",
              pathname === item.href || pathname.startsWith(item.href + "/")
                ? "bg-accent text-accent-foreground"
                : "transparent"
            )}
          >
            <item.icon className="mr-2 h-4 w-4" />
            {item.title}
          </Link>
        ))}
      </div>
    </div>
  );
}

export function Sidebar() {
  const { isAdmin } = useAuth();

  return (
    <div className="flex h-full w-64 flex-col border-r bg-background">
      <div className="flex h-14 items-center border-b px-6">
        <Link href="/" className="flex items-center gap-2 font-semibold">
          <Key className="h-6 w-6" />
          <span>sshmgr</span>
        </Link>
      </div>
      <div className="flex-1 overflow-y-auto py-2">
        <NavSection title="User" items={userNavItems} />
        <Separator className="my-2" />
        <NavSection title="Admin" items={adminNavItems} />
        {isAdmin && (
          <>
            <Separator className="my-2" />
            <NavSection title="Configuration" items={configNavItems} />
          </>
        )}
      </div>
    </div>
  );
}
