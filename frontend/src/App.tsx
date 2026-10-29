import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from './contexts/AuthContext';
import { ThemeProvider } from './contexts/ThemeContext';
import { DashboardLayout } from './layouts/DashboardLayout';
import { ProtectedRoute } from './components/ProtectedRoute';
import { ToastProvider } from './components/ui/Toast';

// Authentication Pages
import { Login } from './pages/Login';
import { Register } from './pages/Register';

// Pillar 1: SECURITY
import { Dashboard } from './pages/Dashboard';
import { SecurityScore } from './pages/SecurityScore';
import { PrivacyScore } from './pages/PrivacyScore';
import { Inbox } from './pages/Inbox';

// Pillar 2: ANALYSIS
import { PhishingDetection } from './pages/PhishingDetection';
import { LinkScanner } from './pages/LinkScanner';
import { AttachmentScanner } from './pages/AttachmentScanner';
import { PrivacyGuardian } from './pages/PrivacyGuardian';

// Pillar 3: OPERATIONS
import { ThreatCenter } from './pages/ThreatCenter';
import { ThreatIntelligence } from './pages/ThreatIntelligence';
import Investigations from './pages/Investigations';
import ResponseOperations from './pages/ResponseOperations';
import { SecurityPolicies } from './pages/SecurityPolicies';
import ResponseEffectiveness from './pages/ResponseEffectiveness';
import ResponseOptimization from './pages/ResponseOptimization';
import ThreatHunting from './pages/ThreatHunting';
import Campaigns from './pages/Campaigns';
import { CopilotChat } from './pages/CopilotChat';

// Pillar 4: GOVERNANCE, AUDIT & SYSTEM
import Governance from './pages/Governance';
import Integrations from './pages/Integrations';
import DataPlatform from './pages/DataPlatform';
import Detections from './pages/Detections';
import { Reports } from './pages/Reports';
import { SystemHealth } from './pages/SystemHealth';
import { Settings } from './pages/Settings';
import { Profile } from './pages/Profile';
import { Sessions } from './pages/Sessions';
import { EmailScans } from './pages/EmailScans';
import { EmailDetail } from './pages/EmailDetail';
import { Incidents } from './pages/Incidents';
import { IncidentDetail } from './pages/IncidentDetail';
import { CyberDefence } from './pages/CyberDefence';

// Initialize React Query client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
});

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <ToastProvider>
          <AuthProvider>
            <BrowserRouter>
            <Routes>
              {/* Public Entry Points */}
              <Route path="/login" element={<Login />} />
              <Route path="/register" element={<Register />} />
              <Route path="/signup" element={<Navigate to="/register" replace />} />

              {/* Protected Administration Console routes */}
              <Route
                path="/*"
                element={
                  <ProtectedRoute>
                    <DashboardLayout>
                      <Routes>
                        {/* 1. SECURITY PILLAR */}
                        <Route path="/" element={<Dashboard />} />
                        <Route path="/dashboard" element={<Navigate to="/" replace />} />
                        <Route path="/security-score" element={<SecurityScore />} />
                        <Route path="/privacy-score" element={<PrivacyScore />} />
                        <Route path="/inbox" element={<Inbox />} />

                        {/* 2. ANALYSIS PILLAR */}
                        <Route path="/detection" element={<PhishingDetection />} />
                        <Route path="/phishing" element={<Navigate to="/detection" replace />} />
                        <Route path="/links" element={<LinkScanner />} />
                        <Route path="/link-scanner" element={<Navigate to="/links" replace />} />
                        <Route path="/attachments" element={<AttachmentScanner />} />
                        <Route path="/attachment-scanner" element={<Navigate to="/attachments" replace />} />
                        <Route path="/privacy" element={<PrivacyGuardian />} />
                        <Route path="/privacy-guardian" element={<Navigate to="/privacy" replace />} />

                        {/* 3. OPERATIONS PILLAR */}
                        <Route path="/threats" element={<ThreatCenter />} />
                        <Route path="/threat-center" element={<Navigate to="/threats" replace />} />
                        <Route path="/threat-intelligence" element={<ThreatIntelligence />} />
                        <Route path="/cyber-defence" element={<CyberDefence />} />
                        <Route path="/advisories" element={<Navigate to="/cyber-defence" replace />} />
                        <Route path="/cert-in" element={<Navigate to="/cyber-defence" replace />} />
                        <Route path="/investigations" element={<Investigations />} />
                        <Route path="/investigations/:id" element={<Investigations />} />
                        <Route path="/security/threat-hunting" element={<ThreatHunting />} />
                        <Route path="/security/campaigns" element={<Campaigns />} />
                        <Route path="/security/copilot" element={<CopilotChat />} />
                        <Route path="/security/detections" element={<Detections />} />
                        <Route path="/enterprise/response-operations" element={<ResponseOperations />} />
                        <Route path="/settings/security/policies" element={<SecurityPolicies />} />
                        <Route path="/enterprise/response-effectiveness" element={<ResponseEffectiveness />} />
                        <Route path="/enterprise/response-optimization" element={<ResponseOptimization />} />

                        {/* 4. GOVERNANCE & AUDIT */}
                        <Route path="/enterprise/governance" element={<Governance />} />
                        <Route path="/audit" element={<Navigate to="/enterprise/governance" replace />} />
                        <Route path="/compliance" element={<Navigate to="/enterprise/governance" replace />} />
                        <Route path="/enterprise/integrations" element={<Integrations />} />
                        <Route path="/enterprise/data-platform" element={<DataPlatform />} />
                        <Route path="/reports" element={<Reports />} />

                        {/* 5. SYSTEM, IDENTITY & EMAILS */}
                        <Route path="/emails" element={<EmailScans />} />
                        <Route path="/emails/:id" element={<EmailDetail />} />
                        <Route path="/incidents" element={<Incidents />} />
                        <Route path="/incidents/:id" element={<IncidentDetail />} />
                        <Route path="/devices" element={<Sessions />} />
                        <Route path="/sessions" element={<Navigate to="/devices" replace />} />
                        <Route path="/profile" element={<Profile />} />
                        <Route path="/settings" element={<Settings />} />
                        <Route path="/system-health" element={<SystemHealth />} />

                        {/* Fallback */}
                        <Route path="*" element={<Navigate to="/" replace />} />
                      </Routes>
                    </DashboardLayout>
                  </ProtectedRoute>
                }
              />
            </Routes>
          </BrowserRouter>
          </AuthProvider>
        </ToastProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

export default App;
