"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import apiClient from "@/lib/api-client";
import type {
  CertType,
  CertificateListParams,
  UserCertificateRequest,
  HostCertificateRequest,
  RevokeRequest,
} from "@/types/api";

export const certificateKeys = {
  all: ["certificates"] as const,
  lists: () => [...certificateKeys.all, "list"] as const,
  list: (envName: string, filters?: CertificateListParams) =>
    [...certificateKeys.lists(), envName, filters] as const,
  detail: (envName: string, serial: number) =>
    [...certificateKeys.all, "detail", envName, serial] as const,
  byKeyId: (envName: string, keyId: string) =>
    [...certificateKeys.all, "byKeyId", envName, keyId] as const,
};

export function useCertificates(envName: string, options?: CertificateListParams) {
  return useQuery({
    queryKey: certificateKeys.list(envName, options),
    queryFn: () => apiClient.listCertificates(envName, options),
    enabled: !!envName,
  });
}

export function useCertificate(envName: string, serial: number) {
  return useQuery({
    queryKey: certificateKeys.detail(envName, serial),
    queryFn: () => apiClient.getCertificate(envName, serial),
    enabled: !!envName && serial > 0,
  });
}

export function useCertificatesByKeyId(envName: string, keyId: string) {
  return useQuery({
    queryKey: certificateKeys.byKeyId(envName, keyId),
    queryFn: () => apiClient.findCertificatesByKeyId(envName, keyId),
    enabled: !!envName && !!keyId,
  });
}

export function useSignUserCertificate(envName: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: UserCertificateRequest) =>
      apiClient.signUserCertificate(envName, data),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: certificateKeys.lists(),
      });
    },
  });
}

export function useSignHostCertificate(envName: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: HostCertificateRequest) =>
      apiClient.signHostCertificate(envName, data),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: certificateKeys.lists(),
      });
    },
  });
}

export function useRevokeCertificate(envName: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({
      serial,
      data,
    }: {
      serial: number;
      data?: RevokeRequest;
    }) => apiClient.revokeCertificate(envName, serial, data),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: certificateKeys.lists(),
      });
    },
  });
}
