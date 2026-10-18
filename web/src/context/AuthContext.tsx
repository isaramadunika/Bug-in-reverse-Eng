import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { apiRequest, setCSRFToken } from '../lib/api';

export interface User {
  id: string;
  email: string;
  display_name: string;
  platform_role: 'user' | 'support_admin' | 'billing_admin' | 'system_admin';
  status: 'active' | 'suspended' | 'pending_deletion';
  email_verified: boolean;
  mfa_enabled: boolean;
  show_onboarding: boolean;
  onboarding_step: number;
  theme_preference: 'dark' | 'light' | 'system';
  created_at: string;
  memberships: Array<{
    organization_id: string;
    organization_name: string;
    role: string;
    is_personal: boolean;
    plan_id: string;
    plan_name: string;
  }>;
}

interface SessionResponse {
  authenticated: boolean;
  mfa_required?: boolean;
  csrf_token?: string;
  user?: User;
}

interface AuthContextType {
  user: User | null;
  loading: boolean;
  mfaPending: boolean;
  checkSession: () => Promise<void>;
  login: (data: SessionResponse) => void;
  logout: () => Promise<void>;
  updateUser: (user: Partial<User>) => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [mfaPending, setMfaPending] = useState(false);

  const checkSession = useCallback(async () => {
    try {
      const resp = await apiRequest<SessionResponse>('/auth/session', { method: 'GET' });
      if (resp.csrf_token) {
        setCSRFToken(resp.csrf_token);
      }
      if (resp.authenticated && resp.user) {
        setUser(resp.user);
        setMfaPending(false);
      } else if (resp.mfa_required) {
        setUser(null);
        setMfaPending(true);
      } else {
        setUser(null);
        setMfaPending(false);
      }
    } catch {
      setUser(null);
      setMfaPending(false);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    checkSession();
  }, [checkSession]);

  const login = (data: SessionResponse) => {
    if (data.csrf_token) {
      setCSRFToken(data.csrf_token);
    }
    if (data.authenticated && data.user) {
      setUser(data.user);
      setMfaPending(false);
    } else if (data.mfa_required) {
      setUser(null);
      setMfaPending(true);
    }
  };

  const logout = async () => {
    try {
      await apiRequest('/auth/logout', { method: 'POST' });
    } finally {
      setUser(null);
      setMfaPending(false);
      setCSRFToken(null);
    }
  };

  const updateUser = (patch: Partial<User>) => {
    setUser((prev) => (prev ? { ...prev, ...patch } : null));
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        mfaPending,
        checkSession,
        login,
        logout,
        updateUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return ctx;
}
