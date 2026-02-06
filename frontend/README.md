# sshmgr Frontend

Next.js web interface for the sshmgr SSH certificate management system.

## Tech Stack

- **Framework**: Next.js 14 (App Router)
- **Styling**: Tailwind CSS + shadcn/ui
- **Authentication**: Auth.js v5 + Keycloak (PKCE flow)
- **Data Fetching**: TanStack Query (React Query)
- **Forms**: react-hook-form + zod
- **Language**: TypeScript

## Quick Start

```bash
# From project root
make frontend-install
make frontend-dev

# Or from frontend directory
npm install
npm run dev
```

The frontend runs on http://localhost:3000

## Environment Setup

1. Copy the example environment file:
```bash
cp .env.example .env.local
```

2. Edit `.env.local` with your configuration:
```env
# Backend API
NEXT_PUBLIC_API_URL=http://localhost:8000

# Keycloak
KEYCLOAK_URL=http://localhost:8080
KEYCLOAK_REALM=sshmgr
KEYCLOAK_CLIENT_ID=sshmgr-web
KEYCLOAK_CLIENT_SECRET=<your-client-secret>

# Auth.js
AUTH_SECRET=<generate-with: openssl rand -base64 32>
AUTH_URL=http://localhost:3000
```

3. Create the `sshmgr-web` client in Keycloak:
   - Client type: OpenID Connect
   - Client authentication: ON (confidential)
   - Valid redirect URIs: `http://localhost:3000/*`
   - Web origins: `http://localhost:3000`

## Project Structure

```
src/
├── app/                      # Next.js App Router
│   ├── (auth)/               # Login, error pages
│   │   ├── login/
│   │   └── error/
│   ├── (dashboard)/          # Protected routes with sidebar
│   │   ├── layout.tsx        # Dashboard shell
│   │   ├── user/             # User section
│   │   │   ├── page.tsx      # Dashboard
│   │   │   ├── certificates/ # My certificates
│   │   │   └── request/      # Request new cert
│   │   ├── admin/            # Admin section
│   │   │   ├── page.tsx      # Dashboard
│   │   │   ├── environments/ # Env management
│   │   │   └── audit/        # Audit logs
│   │   └── config/           # Configuration
│   │       ├── users/        # Keycloak admin
│   │       └── settings/     # System settings
│   └── api/auth/             # Auth.js handler
├── components/
│   ├── ui/                   # shadcn/ui components
│   ├── layout/               # Header, sidebar, breadcrumbs
│   └── certificates/         # Certificate components
├── hooks/
│   ├── use-auth.ts           # Auth hook with role checking
│   ├── use-environments.ts   # Environment React Query hooks
│   └── use-certificates.ts   # Certificate React Query hooks
├── lib/
│   ├── auth.ts               # Auth.js configuration
│   ├── api-client.ts         # Type-safe API client
│   └── utils.ts              # Utility functions
├── providers/
│   └── index.tsx             # Auth + Query providers
└── types/
    └── api.ts                # API type definitions
```

## Available Scripts

```bash
npm run dev          # Start development server
npm run build        # Build for production
npm run start        # Start production server
npm run lint         # Run ESLint
npm run typecheck    # Run TypeScript checker
npm run test         # Run tests
npm run format       # Format code with Prettier
```

## Three Main Sections

### User Section (`/user`)
- **Dashboard**: Overview of certificates and quick actions
- **My Certificates**: View certificates issued to you
- **Request Certificate**: Request new user certificate (operator+)

### Admin Section (`/admin`)
- **Dashboard**: System metrics and health status
- **Environments**: List, create, delete environments
- **Environment Detail**: View CA keys, manage certificates
- **Sign Certificate**: Sign user or host certificates
- **CA Rotation**: Rotate CA with grace period
- **Audit Logs**: View certificate history

### Configuration Section (`/config`)
- **User Management**: Link to Keycloak admin console
- **System Settings**: View system configuration

## Role-Based Access

| Role | User Section | Admin Section | Config Section |
|------|--------------|---------------|----------------|
| viewer | View own certs | View envs* | - |
| operator | + Request certs | + Sign/revoke certs* | - |
| admin | Full access | Full access | Full access |

*Environment access controlled by Keycloak groups (`/environments/{name}`)

## Authentication

The frontend uses Auth.js with Keycloak provider:

1. User clicks "Sign in" → redirects to Keycloak
2. User authenticates → redirects back with code
3. Auth.js exchanges code for tokens (PKCE)
4. JWT contains roles and groups for authorization
5. Token refresh handled automatically

### Using the Auth Hook

```typescript
import { useAuth } from "@/hooks/use-auth";

function MyComponent() {
  const {
    user,
    isAuthenticated,
    isAdmin,
    isOperator,
    hasMinimumRole,
    canAccessEnvironment,
    accessibleEnvironments,
  } = useAuth();

  if (hasMinimumRole("operator")) {
    // Show operator features
  }

  if (canAccessEnvironment("prod")) {
    // User can access prod environment
  }
}
```

## API Integration

### Type-Safe API Client

```typescript
import apiClient from "@/lib/api-client";

// Automatically includes auth header
const envs = await apiClient.listEnvironments();
const cert = await apiClient.signUserCertificate("prod", {
  public_key: "ssh-ed25519 AAAA...",
  principals: ["username"],
  key_id: "user@example.com",
});
```

### React Query Hooks

```typescript
import { useEnvironments, useCreateEnvironment } from "@/hooks/use-environments";

// Fetch with caching
const { data, isLoading, error } = useEnvironments();

// Mutations with auto-invalidation
const createMutation = useCreateEnvironment();
createMutation.mutate({ name: "staging", key_type: "ed25519" });
```

## Development

### Adding New Pages

1. Create page in `src/app/(dashboard)/section/page.tsx`
2. Add navigation item in `src/components/layout/sidebar.tsx`
3. Add breadcrumb label in `src/components/layout/breadcrumbs.tsx`

### Adding UI Components

Using shadcn/ui CLI (if configured):
```bash
npx shadcn-ui@latest add button
```

Or copy from [ui.shadcn.com](https://ui.shadcn.com) into `src/components/ui/`

### Adding API Endpoints

1. Add types in `src/types/api.ts`
2. Add method in `src/lib/api-client.ts`
3. Add React Query hook in `src/hooks/`

## Production Build

```bash
# Build
npm run build

# Start production server
npm start
```

## Docker Deployment

The frontend is containerized using a multi-stage Docker build with Next.js standalone output.

### Build the Image

```bash
# Build frontend image only
docker build -t sshmgr-frontend:latest ./frontend

# Or use docker-compose to build everything
docker compose -f docker-compose.prod.yml build frontend
```

### Environment Variables (Production)

| Variable | Description | Required |
|----------|-------------|----------|
| `AUTH_SECRET` | Auth.js session encryption key | Yes |
| `AUTH_URL` | Frontend URL (e.g., `https://sshmgr.example.com`) | Yes |
| `KEYCLOAK_URL` | Keycloak URL for auth redirects | Yes |
| `KEYCLOAK_REALM` | Keycloak realm name | Yes |
| `KEYCLOAK_CLIENT_ID` | Web client ID (`sshmgr-web`) | Yes |
| `KEYCLOAK_CLIENT_SECRET` | Web client secret | Yes |
| `NEXT_PUBLIC_API_URL` | Backend API URL | Yes |

### Full Stack Deployment

```bash
# From project root
make prod-up
```

Services available at:
- Frontend: `https://${DOMAIN}`
- API: `https://api.${DOMAIN}`
- Keycloak: `https://auth.${DOMAIN}`

See the main project's `docker-compose.prod.yml` for the complete stack configuration.
