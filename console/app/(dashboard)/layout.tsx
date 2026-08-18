"use client";

import { Sidebar } from "@/components/sidebar";
import { CommandPalette } from "@/components/command-palette";
import { AuthProvider, useAuth } from "@/components/auth-provider";
import { LoginScreen } from "@/components/login-screen";

/** Renders the login screen instead of the dashboard until AuthProvider reports
 *  a valid credential. See components/auth-provider.tsx and lib/auth/session.ts. */
function AuthGate({ children }: { children: React.ReactNode }) {
  const { authenticated } = useAuth();

  if (!authenticated) return <LoginScreen />;

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />
      <main className="flex-1 overflow-y-auto">{children}</main>
      <CommandPalette />
    </div>
  );
}

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <AuthProvider>
      <AuthGate>{children}</AuthGate>
    </AuthProvider>
  );
}
