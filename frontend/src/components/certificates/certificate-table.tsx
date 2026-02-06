"use client";

import Link from "next/link";
import { formatDate } from "@/lib/utils";
import { getCertificateStatus, type Certificate } from "@/types/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Eye, Ban } from "lucide-react";

interface CertificateTableProps {
  certificates: Certificate[];
  envName: string;
  showActions?: boolean;
  onRevoke?: (serial: number) => void;
}

export function CertificateTable({
  certificates,
  envName,
  showActions = true,
  onRevoke,
}: CertificateTableProps) {
  const getStatusBadge = (cert: Certificate) => {
    const status = getCertificateStatus(cert);
    switch (status) {
      case "valid":
        return <Badge variant="success">Valid</Badge>;
      case "expired":
        return <Badge variant="secondary">Expired</Badge>;
      case "revoked":
        return <Badge variant="destructive">Revoked</Badge>;
    }
  };

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Serial</TableHead>
          <TableHead>Type</TableHead>
          <TableHead>Key ID</TableHead>
          <TableHead>Principals</TableHead>
          <TableHead>Valid Until</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Issued By</TableHead>
          {showActions && <TableHead className="w-24">Actions</TableHead>}
        </TableRow>
      </TableHeader>
      <TableBody>
        {certificates.map((cert) => (
          <TableRow key={cert.id}>
            <TableCell className="font-mono">{cert.serial}</TableCell>
            <TableCell>
              <Badge variant="outline">
                {cert.cert_type.toUpperCase()}
              </Badge>
            </TableCell>
            <TableCell className="font-mono text-sm">{cert.key_id}</TableCell>
            <TableCell>
              <div className="flex flex-wrap gap-1">
                {cert.principals.slice(0, 2).map((p) => (
                  <Badge key={p} variant="secondary" className="text-xs">
                    {p}
                  </Badge>
                ))}
                {cert.principals.length > 2 && (
                  <Badge variant="secondary" className="text-xs">
                    +{cert.principals.length - 2}
                  </Badge>
                )}
              </div>
            </TableCell>
            <TableCell className="text-sm">
              {formatDate(cert.valid_before)}
            </TableCell>
            <TableCell>{getStatusBadge(cert)}</TableCell>
            <TableCell className="text-sm">{cert.issued_by}</TableCell>
            {showActions && (
              <TableCell>
                <div className="flex items-center gap-1">
                  <Button asChild variant="ghost" size="icon">
                    <Link href={`/admin/environments/${envName}/certificates/${cert.serial}`}>
                      <Eye className="h-4 w-4" />
                    </Link>
                  </Button>
                  {getCertificateStatus(cert) === "valid" && onRevoke && (
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => onRevoke(cert.serial)}
                    >
                      <Ban className="h-4 w-4 text-destructive" />
                    </Button>
                  )}
                </div>
              </TableCell>
            )}
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
