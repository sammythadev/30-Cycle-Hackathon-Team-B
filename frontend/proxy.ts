import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export default function middleware(request: NextRequest) {
  const token = request.cookies.get('ciap_access')?.value;
  const { pathname } = request.nextUrl;

  const isApiProxy = pathname.startsWith('/api-proxy');

  const isAuthPage = pathname.startsWith('/login') || pathname.startsWith('/signup') || pathname.startsWith('/onboarding') || pathname.startsWith('/welcome');
  const isCallbackPage = pathname.startsWith('/callback');
  const isLandingPage = pathname === '/';
  
  // Always allow API proxy traffic to reach backend routes.
  // If a token exists, inject it as Bearer for backend auth.
  if (isApiProxy) {
    const headers = new Headers(request.headers);
    if (token && !headers.get('authorization')) {
      headers.set('authorization', `Bearer ${token}`);
    }
    return NextResponse.next({ request: { headers } });
  }

  // Allow landing and auth pages without tokens
  if (!token && !isAuthPage && !isCallbackPage && !isLandingPage) {
    return NextResponse.redirect(new URL('/login', request.url));
  }

  // If already logged in, redirect landing/auth to dashboard
  if (token && (isAuthPage || isCallbackPage || isLandingPage)) {
    return NextResponse.redirect(new URL('/dashboard', request.url));
  }

  return NextResponse.next();
}

export const config = {
  // Exclude static assets (jpg, png, svg, etc.) so they load via public/
  matcher: [
    '/api-proxy/:path*',
    '/((?!api|_next/static|_next/image|favicon.ico|.*\\.jpg$|.*\\.png$|.*\\.svg$).*)',
  ],
};
