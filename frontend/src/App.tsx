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
import { ThreatIntelligence } from './pages/ThreatIntelligence';
import { SecurityPolicies } from './pages/SecurityPolicies';
import { CopilotChat } from './pages/CopilotChat';
import Governance from './pages/Governance';
import Integrations from './pages/Integrations';
import DataPlatform from './pages/DataPlatform';
import Detections from './pages/Detections';
import Investigations from './pages/Investigations';

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
                        
                        {/* Governance, Risk & Compliance (GRC) Workspace */}
                        <Route 
                          path="/enterprise/governance" 
                          element={
                            <ProtectedRoute allowedRoles={['admin', 'soc_analyst', 'security_analyst']}>
                              <Governance />
                            </ProtectedRoute>
                          } 
                        />
                        <Route path="/enterprise/compliance" element={<Navigate to="/enterprise/governance" replace />} />
                        <Route path="/enterprise/risk" element={<Navigate to="/enterprise/governance" replace />} />
                        <Route path="/enterprise/audits" element={<Navigate to="/enterprise/governance" replace />} />
                        <Route path="/enterprise/evidence" element={<Navigate to="/enterprise/governance" replace />} />
                        <Route path="/enterprise/reports" element={<Navigate to="/enterprise/governance" replace />} />

                        {/* Integrations Workspace */}
                        <Route 
                          path="/enterprise/integrations" 
                          element={
                            <ProtectedRoute allowedRoles={['admin', 'soc_analyst', 'security_analyst']}>
                              <Integrations />
                            </ProtectedRoute>
                          } 
                        />

                        {/* Data Platform Workspace */}
                        <Route 
                          path="/enterprise/data-platform" 
                          element={
                            <ProtectedRoute allowedRoles={['admin', 'soc_analyst', 'security_analyst']}>
                              <DataPlatform />
                            </ProtectedRoute>
                          } 
                        />

                        {/* Detection Engineering Workspace */}
                        <Route 
                          path="/security/detections" 
                          element={
                            <ProtectedRoute allowedRoles={['admin', 'soc_analyst', 'security_analyst']}>
                              <Detections />
                            </ProtectedRoute>
                          } 
                        />

                        {/* Investigations Workspace */}
                        <Route 
                          path="/security/investigations" 
                          element={
                            <ProtectedRoute allowedRoles={['admin', 'soc_analyst', 'security_analyst']}>
                              <Investigations />
                            </ProtectedRoute>
                          } 
                        />

                        {/* Threat Intelligence Platform & Hunting */}
                        <Route 
                          path="/threat-intelligence" 
                          element={
                            <ProtectedRoute allowedRoles={['admin', 'soc_analyst', 'security_analyst']}>
                              <ThreatIntelligence />
                            </ProtectedRoute>
                          } 
                        />

                        {/* Security Policy Center */}
                        <Route 
                          path="/settings/security/policies" 
                          element={
                            <ProtectedRoute allowedRoles={['admin']}>
                              <SecurityPolicies />
                            </ProtectedRoute>
                          } 
                        />

                        {/* AI Copilot & Chat Operations */}
                        <Route 
                          path="/security/copilot" 
                          element={
                            <ProtectedRoute allowedRoles={['admin', 'soc_analyst', 'security_analyst']}>
                              <CopilotChat />
                            </ProtectedRoute>
                          } 
                        />
                        
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
