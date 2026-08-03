# Enterprise Frontend Engineering Specification: GuardianMail AI

---

## Section 1: Frontend Vision

GuardianMail AI's frontend is an accessibility-first React single-page application (SPA) optimized for low latency and visual clarity:
- **Zero-Friction UX**: Provides responsive dashboards and interactive threat timelines to enable rapid threat analysis.
- **Enterprise Usability & Accessibility**: Built to satisfy WCAG 2.2 AA guidelines, supporting full keyboard navigation and screen readers.
- **Secure Architecture**: Enforces secure token handling, Content Security Policies (CSP), and sensitive data masking to protect the analyst workflow.

---

## Section 2: Folder Structure

```
guardianmail-frontend/
├── public/                 # Static public assets
├── src/
│   ├── app/                # Application shell, router providers
│   ├── components/
│   │   ├── ui/             # Reusable UI component library (shadcn/ui atoms)
│   │   └── common/         # Layout systems (AppShell, Navigation)
│   ├── features/           # Domain-driven feature directories
│   │   ├── auth/           # Login, register, MFA screens
│   │   ├── dashboard/      # Executive dashboards, metric graphs
│   │   └── scanner/        # File drop, timeline, risk views
│   ├── hooks/              # Global custom hooks (e.g. useAuth)
│   ├── services/           # Axios clients and interceptors
│   ├── styles/             # Tailwind CSS entrypoint
│   └── types/              # Statically typed TS interfaces
```

---

## Section 3: Application Architecture

- **App Shell**: A persistent navbar and sidebar layout wrapped in dynamic suspense loaders.
- **Code Splitting**: Route-level code splitting using dynamic `React.lazy()` imports.
- **Strict Boundaries**: Prevents circular dependencies between feature directories.

---

## Section 4: Design System

- **Color Palette (Dark Mode)**:
  - Background: HSL `224 71% 4%` (Deep navy midnight)
  - Card: HSL `224 71% 7%`
  - Accent Red (Phishing): HSL `0 84% 60%`
  - Accent Green (Safe): HSL `142 70% 45%`
- **Typography**: Inter (primary sans-serif) with Outfit for dashboard headings.
- **Micro-Animations**: Smooth scale changes on button hovers and keyframe loaders for scanner states.

---

## Section 5: Component Architecture & Atomic Design

- **Atoms**: Primitive UI controls (Buttons, Inputs, Badges, Tooltips).
- **Molecules**: Combined controls (FormField inputs, search blocks, dropdown buttons).
- **Organisms**: Complex features (ThreatTimeline, UploadZone, MetricGrid).
- **Templates**: Page shell grids defining sidebar and header layouts.
- **Pages**: Content-filled layouts injected into React Router outputs.

---

## Section 6: Routing Configuration

- **Protected Routes**: Custom navigation guards verify active session states before rendering dashboard elements.
- **Nested Views**: Incident detail interfaces use sub-routing templates.
- **Error Routing**: Declares fallback routers for 404 Not Found and 403 Forbidden views.

---

## Section 7: Authentication UI

- **Google OAuth Integration**: Provides one-click directory authentication buttons.
- **MFA Challenge Panel**: Prompts for 6-digit authenticator verification tokens.
- **Session Timers**: Detects inactivity, displaying warning modals before clearing storage tokens.

---

## Section 8: Dashboard Layout Panels

- **Executive Posture Card**: Renders top-level KPIs (Total Mails Scanned, Block Rate, Risk posturing scores).
- **SOC Incident Queue**: Provides search filters, priority status tags, and bulk containment checkboxes.
- **Threat Category breakdown**: Visualizes risk distribution charts.

---

## Section 9: Threat Scanner Drag & Drop

- **Upload zone**: Implements HTML5 drag-and-drop file inputs.
- **State indicators**: Displays circular loaders tracking Upload, Parse, and Classification task steps.
- **Indicators Timeline**: Renders chronological indicator flags (failed DKIM, phishing URL detected).

---

## Section 10: Evidence & Complaint UI

- **Evidence Package Viewer**: Displays raw text bodies, decrypted screenshots, and parsed header tables.
- **Complaint Wizard**: A multi-step form to generate cybercrime reports, preview formatting, and copy/export data.

---

## Section 11: State Management

- **Global State (Zustand)**: Manages local sidebar configurations, active tenant contexts, and user profiles.
- **Server State (TanStack Query)**: Directs endpoint query caching, auto-retries, and cache evictions.

---

## Section 12: API Integration Layer

- **Axios Client**: Configured with a default base URL and timeout parameters.
- **Request Interceptors**: Inject active JWT authorization tokens into header strings.
- **Response Interceptors**: Intercept `401 Unauthorized` responses to trigger token refresh workflows.

---

## Section 13: Forms Validation

- Fields validation uses React Hook Form integrated with Zod validation schemas.
- Error alerts declare matching ARIA attributes (`aria-invalid="true"`) to support screen readers.

---

## Section 14: Data Visualizations

- Recharts visualizations:
  - **Risk Line Chart**: Chronological threat distributions.
  - **Phishing Categories Pie Chart**: Threat classifications breakdown.

---

## Section 15: Accessibility Compliance (WCAG 2.2 AA)

- Enforces a minimum color contrast ratio of 4.5:1 for standard text.
- Implements focus traps inside dialog overlays to ensure keyboard accessibility.
- Interactive elements declare proper ARIA labels and roles.

---

## Section 16: Performance Optimizations

- Large lists (e.g. SOC incident queue) are virtualized using dynamic row render lists.
- Avoids redundant component re-renders using `useMemo` and `useCallback` hooks.

---

## Section 17: Security Practices

- Escapes raw body text strings to protect against Cross-Site Scripting (XSS).
- Employs secure memory state closures for JWT access tokens.
- Masks sensitive values (like API keys) in settings views.

---

## Section 18: Notification Toast Systems

- Visual toasts use distinct states: Success, Warning, Error, and Info.
- Action toasts enable quick undo options (e.g., "Email Quarantined - Undo").

---

## Section 19: Internationalization (i18n)

- Standardizes i18n configurations using translation files.
- Formats dates and times according to local system timezones.

---

## Section 20: Testing Frameworks

- **Vitest & React Testing Library**: Evaluates isolated component behaviors.
- **Playwright**: Directs end-to-end browser tests.
- **Axe-core**: Runs automated accessibility compliance checks during unit test suites.

---

## Section 21: Frontend Monitoring

- Tracks page performance metrics (LCP, FID, CLS) and forwards events to log endpoints.
- Global Error Boundaries capture runtime errors, displaying fallback layouts.

---

## Section 22: Architectural Decision Records (ADRs)

### ADR-05: Zustand over Redux
* **Decision**: Adopt Zustand for global UI state management.
* **Trade-off**: Redux is mature but boilerplate-heavy. Zustand provides a minimal hook-based API, does not require context providers, and keeps bundle sizes minimal, satisfying our performance goals.
