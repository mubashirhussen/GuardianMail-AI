import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from './contexts/AuthContext';
import { ThemeProvider } from './contexts/ThemeContext';
import { DashboardLayout } from './layouts/DashboardLayout';
import { ProtectedRoute } from './components/ProtectedRoute';

// Import Pages
import { Login } from './pages/Login';
import { Register } from './pages/Register';
import { Dashboard } from './pages/Dashboard';
import { EmailScans } from './pages/EmailScans';
import { EmailDetail } from './pages/EmailDetail';
import { Incidents } from './pages/Incidents';
import { IncidentDetail } from './pages/IncidentDetail';
import { Reports } from './pages/Reports';
import { Devices } from './pages/Devices';
import { SystemHealth } from './pages/SystemHealth';
import { Profile } from './pages/Profile';
import { Settings } from './pages/Settings';

// Initialize React Query client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1
    }
  }
});

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <AuthProvider>
          <BrowserRouter>
            <Routes>
              {/* Public Entry Points */}
              <Route path="/login" element={<Login />} />
              <Route path="/register" element={<Register />} />

              {/* Protected Administration Console routes */}
              <Route
                path="/*"
                element={
                  <ProtectedRoute>
                    <DashboardLayout>
                      <Routes>
                        <Route path="/" element={<Dashboard />} />
                        <Route path="/emails" element={<EmailScans />} />
                        <Route path="/emails/:id" element={<EmailDetail />} />
                        <Route path="/incidents" element={<Incidents />} />
                        <Route path="/incidents/:id" element={<IncidentDetail />} />
                        <Route path="/reports" element={<Reports />} />
                        <Route path="/devices" element={<Devices />} />
                        
                        {/* Admin / SOC Analyst Diagnostics */}
                        <Route 
                          path="/system-health" 
                          element={
                            <ProtectedRoute allowedRoles={['admin', 'soc_analyst']}>
                              <SystemHealth />
                            </ProtectedRoute>
                          } 
                        />

                        {/* Account Profiles & Settings */}
                        <Route path="/profile" element={<Profile />} />
                        <Route path="/settings" element={<Settings />} />

                        {/* Fallback route */}
                        <Route path="*" element={<Navigate to="/" replace />} />
                      </Routes>
                    </DashboardLayout>
                  </ProtectedRoute>
                }
              />
            </Routes>
          </BrowserRouter>
        </AuthProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

export default App;
