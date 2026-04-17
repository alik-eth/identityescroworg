import type { ReactNode } from 'react';

export type Role = 'holder' | 'custodian' | 'recipient';

/** Palette tokens per role. Tailwind v4 has no config file here — classes come
 *  from the utility set; we pick representative amber/blue/emerald scales for
 *  surface + ring + text so downstream components can scope color via
 *  `group-data-[role=custodian]` selectors or plain `data-role`-targeted CSS. */
const ROLE_SURFACE: Record<Role, string> = {
  holder: 'bg-slate-900/40 ring-blue-500/20 text-blue-100',
  custodian: 'bg-amber-950/20 ring-amber-500/20 text-amber-100',
  recipient: 'bg-emerald-950/20 ring-emerald-500/20 text-emerald-100',
};

export function RoleShell({
  role,
  children,
  className = '',
}: {
  role: Role;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section
      data-testid="role-shell"
      data-role={role}
      className={`group ring-1 rounded-lg ${ROLE_SURFACE[role]} ${className}`}
    >
      {children}
    </section>
  );
}
