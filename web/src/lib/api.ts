/**
 * ReverseBug Typed API Client
 * Manages CSRF tokens, credentials, and typed errors.
 */

export interface APIErrorResponse {
  error: {
    code: string;
    message: string;
    fields?: Record<string, string>;
    request_id?: string;
  };
}

export class APIClientError extends Error {
  code: string;
  fields?: Record<string, string>;
  requestId?: string;
  status: number;

  constructor(status: number, data: APIErrorResponse) {
    super(data.error?.message || 'An unexpected error occurred');
    this.name = 'APIClientError';
    this.status = status;
    this.code = data.error?.code || 'unknown_error';
    this.fields = data.error?.fields;
    this.requestId = data.error?.request_id;
  }
}

let currentCSRFToken: string | null = null;

export function setCSRFToken(token: string | null) {
  currentCSRFToken = token;
}

export function getCSRFToken(): string | null {
  return currentCSRFToken;
}

const API_BASE = '/api/v1';

export async function apiRequest<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const headers = new Headers(options.headers || {});

  // Add CSRF token on state-changing requests if present
  if (
    currentCSRFToken &&
    options.method &&
    !['GET', 'HEAD', 'OPTIONS'].includes(options.method.toUpperCase())
  ) {
    headers.set('X-CSRF-Token', currentCSRFToken);
  }

  if (!headers.has('Content-Type') && !(options.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json');
  }

  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers,
    credentials: 'include', // send session cookies
  });

  if (response.status === 204) {
    return {} as T;
  }

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    if (response.status === 401 && !endpoint.includes('/auth/')) {
      const path = window.location.pathname;
      const isPublic = ['/login', '/register', '/forgot-password', '/reset-password', '/verify-email', '/', '/features', '/how-it-works', '/methodology', '/pricing', '/docs', '/sample-report'].includes(path);
      if (!isPublic) {
        window.location.href = '/login?expired=true';
      }
    }
    throw new APIClientError(response.status, data as APIErrorResponse);
  }

  // Update stored CSRF token if returned in response
  if (data && typeof data === 'object' && 'csrf_token' in data && data.csrf_token) {
    setCSRFToken(data.csrf_token);
  }

  return data as T;
}
