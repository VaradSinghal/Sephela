'use client';

import { useMutation, useQuery } from '@tanstack/react-query';
import { useRouter } from 'next/navigation';
import { authApi } from '@/lib/api/endpoints';
import { useAuthStore } from '@/lib/state/auth-store';

export function useLogin() {
  const router = useRouter();
  const setAuth = useAuthStore((s) => s.setAuth);
  return useMutation({
    mutationFn: (vars: { email: string; password: string }) =>
      authApi.login(vars.email, vars.password),
    onSuccess: (token) => {
      setAuth(token.access_token, token.refresh_token);
      router.push('/dashboard');
    },
  });
}

export function useCurrentUser() {
  const token = useAuthStore((s) => s.token);
  return useQuery({
    queryKey: ['me'],
    queryFn: authApi.me,
    enabled: Boolean(token),
  });
}

export function useLogout() {
  const router = useRouter();
  const logout = useAuthStore((s) => s.logout);
  return () => {
    logout();
    router.push('/login');
  };
}
