"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import apiClient from "@/lib/api-client";
import type { EnvironmentCreate, RotateCARequest, CertType } from "@/types/api";

export const environmentKeys = {
  all: ["environments"] as const,
  lists: () => [...environmentKeys.all, "list"] as const,
  detail: (name: string) => [...environmentKeys.all, "detail", name] as const,
  ca: (name: string, type: CertType) =>
    [...environmentKeys.all, "ca", name, type] as const,
  rotation: (name: string) =>
    [...environmentKeys.all, "rotation", name] as const,
};

export function useEnvironments() {
  return useQuery({
    queryKey: environmentKeys.lists(),
    queryFn: () => apiClient.listEnvironments(),
  });
}

export function useEnvironment(name: string) {
  return useQuery({
    queryKey: environmentKeys.detail(name),
    queryFn: () => apiClient.getEnvironment(name),
    enabled: !!name,
  });
}

export function useCAPublicKey(
  envName: string,
  caType: CertType,
  includeOld = false
) {
  return useQuery({
    queryKey: [...environmentKeys.ca(envName, caType), includeOld],
    queryFn: () => apiClient.getCAPublicKey(envName, caType, includeOld),
    enabled: !!envName,
  });
}

export function useRotationStatus(envName: string) {
  return useQuery({
    queryKey: environmentKeys.rotation(envName),
    queryFn: () => apiClient.getRotationStatus(envName),
    enabled: !!envName,
  });
}

export function useCreateEnvironment() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: EnvironmentCreate) => apiClient.createEnvironment(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: environmentKeys.lists() });
    },
  });
}

export function useDeleteEnvironment() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (name: string) => apiClient.deleteEnvironment(name),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: environmentKeys.lists() });
    },
  });
}

export function useRotateCA(envName: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: RotateCARequest) => apiClient.rotateCA(envName, data),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: environmentKeys.detail(envName),
      });
      queryClient.invalidateQueries({
        queryKey: environmentKeys.rotation(envName),
      });
    },
  });
}
