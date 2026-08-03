import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { Loader } from './Loader';

interface ProtectedRouteProps {
  children: React.ReactNode;
  allowedRoles?: Array<'admin' | 'soc_analyst' | 'security_analyst' | 'user'>;
}

export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ children, allowedRoles }) => {
  const { user, loading } = useAuth();
  const location = useLocation();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-950">
        <Loader />
      </div>
    );
  }

  if (!user) {
    // Redirect to login but keep target location context
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (allowedRoles) {
    const hasRole = allowedRoles.includes(user.role);
    if (!hasRole) {
      // Redirect standard user
      return <Navigate to="/" replace />;
    }
  }

  return <>{children}</>;
};
