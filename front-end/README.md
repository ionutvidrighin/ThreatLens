# ThreatLens admin dashboard

React + TypeScript + Vite, with Cognito authorization code + PKCE through react-oidc-context / oidc-client-ts. The dashboard reads rules and supports partial updates for sessions with the write scope.

## Run locally

Use Node.js 24 LTS and npm. From this directory:

```powershell
npm install
Copy-Item .env.example .env.local
npm run dev
```

Review the public AWS identifiers in `.env.local` against your account before signing in. Open http://localhost:5173. Vite keeps this port fixed to match Cognito. Restart Vite after environment changes. No AWS credentials or client secret belong in this browser app: all `VITE_` variables are public in the bundle.

If npm is missing from PATH, open a terminal with Node.js installed/configured. A lockfile pins installed dependencies; use `npm ci` on subsequent clean installs.

## AWS configuration

Cognito app client (public SPA, no secret):

- Allowed callback: `http://localhost:5173/callback`
- Allowed sign-out: `http://localhost:5173/`
- Authorization code grant, with `openid`, `email`, `threatlens-api/rules.read`, and `threatlens-api/rules.write` enabled.
- Keep existing Postman callbacks while they are still used.

API Gateway HTTP API CORS:

- Allowed origins: `http://localhost:5173`
- Allowed methods: `GET`, `PATCH`, `OPTIONS`.
- Allowed headers: `Authorization`, `Content-Type`.
- Credentials: disabled (the app uses bearer tokens, not cookies).
- Save and deploy the API stage. CORS is configured on API Gateway, not this Lambda.
- If a protected `$default` route exists, ensure preflight OPTIONS is handled without JWT authentication.

Keep JWT authorizers/scopes attached. CORS is a browser rule, not API authorization.

Sign-in and sign-out use Cognito's managed login. Tokens/state use this tab's sessionStorage; tokens are never logged or placed in URLs by the app. Refresh-token renewal is handled by the OIDC library. The OAuth callback cleans the code/state out of the URL. Session expiry and API errors have explicit UI states.

## Commands

- `npm run dev`: local server on port 5173.
- `npm run typecheck`: strict TypeScript source check.
- `npm run build`: typecheck and production output in `dist/`.
- `npm run preview`: preview build on 4173; authentication needs matching Cognito callback/logout URLs and CORS if used there.

Production hosting must serve `index.html` for `/callback` as well as `/`. Set production public URLs at build time, register exact HTTPS callback/logout URLs in Cognito, and update API CORS. No hosting/deployment is performed by this scaffold.

## Structure

- `src/config.ts`: validated environment configuration and friendly setup state.
- `src/auth.ts`: Cognito/OIDC integration.
- `src/api/rules.ts`: authenticated API request and runtime response validation.
- `src/query/QueryProvider.tsx`: a session-scoped React Query cache, cleared when the session ends.
- `src/query/useRules.ts`: authenticated rules query, cancellation, 30-second stale time, and at most two retries for transient failures. Authorization/client validation errors are not retried.
- `src/App.tsx`: signed-out and rule administration views using React Query loading/error/refresh state.
- `src/styles.css`: responsive dashboard styles.

## Verification

Run `npm run build`. Live sign-in and rules retrieval additionally require the AWS configuration above. Existing Lambda tests do not cover the browser integration.

React Query owns server state and uses the API function as its query function. Axios is the HTTP transport; Zod continues validating responses. Access tokens are not included in cache keys or persisted by React Query. Background refetches use the latest token without creating token-specific cache entries.

## Notifications

Sonner renders dismissible success/error toasts in the top-right corner. Sign-in completion, sign-in/callback failures, sign-out failures, rules request failures, and manual refresh success use toasts. Query-cache errors notify once after retries finish, with stable toast IDs to avoid stacked duplicates; a later successful fetch dismisses the rules error. Loading, empty, and setup instructions remain on the page. Use `toast` from `src/notifications.ts` for future action messages.

The Axios rules request forwards React Query's AbortSignal and passes the current bearer token per request. HTTP failures become RulesApiError, network failures retain a friendly transport-independent message, and cancellation is propagated unchanged. Zod validates response.data before it enters the query cache.

## Editing rules

Restart Vite after changing `.env.local`; sign out and sign back in to obtain `threatlens-api/rules.write`. Edit actions are shown only when the access token contains this scope. API Gateway must independently require the write scope on PATCH.

The editor sends only changed fields plus the timestamp captured when the form opened. Successful saves update the React Query cache and revalidate the rule list. Mutations never retry automatically. On 409 or an uncertain network/response result, saving is disabled until Reload latest values replaces the draft. A failed reload preserves the draft. Updates affect live detection settings; changes may take up to 60 seconds to reach detection-engine caches.

Verification: TypeScript and Vite build checks cover compilation. Live editing, conflict handling, dialog keyboard interaction, and write-scope behavior still need browser verification.

## Routes

React Router declarative routes are defined in `src/App.tsx`:

- `/` redirects to `/rules` with history replacement.
- `/rules` uses ProtectedRoute: waits for session initialization, shows sign-in for visitors, and mounts RulesPage only for authenticated users.
- `/callback` renders Cognito completion or a recoverable sign-in error. RouterAuthProvider lets the OIDC library process this callback and navigates to `/rules` with replacement, removing OAuth parameters.
- All other URLs display NotFoundPage.

AppLayout owns the header/footer and renders an Outlet. AppHeader uses Link for local navigation; Cognito login/logout still require external redirects. Production hosting must fall back to `index.html` for `/rules` and `/callback` (not just `/`). Cognito callback remains `http://localhost:5173/callback` and sign-out remains `http://localhost:5173/`; no new AWS callback URL is required.

The client-side protected route controls rendering only. API Gateway JWT scopes remain the authorization boundary for reads and writes. Verify callback sign-in, direct `/rules` loads, session expiry, logout, back navigation, and unknown routes in the browser.

## Overview and navigation

The landing page is now `/overview`, including after Cognito sign-in. `/rules` remains the detection-rule administration page. The sidebar highlights active routes and lists Alerts, Authentication Events, and Network Events as planned, non-interactive sections. On small screens navigation moves above the content.

Overview uses the existing rules query/cache for enabled-rule totals and the rule-status doughnut chart. Open alerts, events today, detection rate, activity history, and recent alerts explicitly display unavailable-data states until corresponding backend endpoints exist. No fabricated security metrics are used. Detection rate needs a defined numerator, denominator, and reporting period before integration. Production hosting must also serve the SPA fallback for `/overview`.
