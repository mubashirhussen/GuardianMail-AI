import React, { createContext, useContext, useEffect, useState } from 'react';
import type { User } from '../types';
import { authService } from '../services/auth';

interface AuthContextType {
  user: User | null;
  loading: boolean;
  login: (payload: any) => Promise<void>;
  register: (payload: any) => Promise<void>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
  isAdminOrAnalyst: () => boolean;
  isAdmin: () => boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  const refreshUser = async () => {
    const token = localStorage.getItem('access_token');
    if (!token) {
      setUser(null);
      setLoading(false);
      return;
    }
    try {
      const u = await authService.getMe();
      setUser(u);
    } catch (err) {
      setUser(null);
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refreshUser();

    // Listen to automatic logout events from axios client
    const handleAutoLogout = () => {
      setUser(null);
    };

    window.addEventListener('auth_logout', handleAutoLogout);
    return () => {
      window.removeEventListener('auth_logout', handleAutoLogout);
    };
  }, []);

  const login = async (payload: any) => {
    const tokens = await authService.login(payload);
    localStorage.setItem('access_token', tokens.access_token);
    localStorage.setItem('refresh_token', tokens.refresh_token);
    await refreshUser();
  };

  const register = async (payload: any) => {
    await authService.register(payload);
  };

  const logout = async () => {
    await authService.logout();
    setUser(null);
  };

  const isAdminOrAnalyst = () => {
    return user ? ['admin', 'soc_analyst', 'security_analyst'].includes(user.role) : false;
  };

  const isAdmin = () => {
    return user ? user.role === 'admin' : false;
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        login,
        register,
        logout,
        refreshUser,
        isAdminOrAnalyst,
        isAdmin,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
