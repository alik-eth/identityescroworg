import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';
import type { Role } from './RoleShell';

const STORAGE_KEY = 'qie.demo.role';

const ROLE_ROUTES: Record<Role, string> = {
  holder: '/escrow/setup',
  custodian: '/custodian',
  recipient: '/escrow/notary',
};

/** Derive a best-guess role from a URL path (used for the initial role
 *  when no localStorage value is set and when syncing on navigation). */
export function roleFromPath(path: string): Role {
  const p = path.split('?')[0] ?? path;
  if (p.startsWith('/custodian')) return 'custodian';
  if (p.startsWith('/escrow/notary') || p.startsWith('/escrow/recover')) {
    return 'recipient';
  }
  return 'holder';
}

interface RoleContextShape {
  role: Role;
  setRole: (r: Role) => void;
}

const RoleContext = createContext<RoleContextShape | null>(null);

export function useRole(): RoleContextShape {
  const ctx = useContext(RoleContext);
  if (!ctx) throw new Error('useRole must be used inside <RoleProvider>');
  return ctx;
}

function readStoredRole(): Role | null {
  try {
    const v = globalThis.localStorage?.getItem(STORAGE_KEY);
    if (v === 'holder' || v === 'custodian' || v === 'recipient') return v;
  } catch {
    // localStorage unavailable (SSR / private mode)
  }
  return null;
}

export function RoleProvider({
  children,
  initialRole,
}: {
  children: ReactNode;
  initialRole?: Role;
}) {
  const computedInitial = useMemo<Role>(() => {
    if (initialRole) return initialRole;
    const stored = readStoredRole();
    if (stored) return stored;
    const path =
      typeof window !== 'undefined' ? window.location.pathname : '/';
    return roleFromPath(path);
  }, [initialRole]);

  const [role, setRoleState] = useState<Role>(computedInitial);

  const setRole = useCallback((r: Role) => {
    setRoleState(r);
    try {
      globalThis.localStorage?.setItem(STORAGE_KEY, r);
    } catch {
      // ignore
    }
  }, []);

  useEffect(() => {
    // Keep state in sync with browser-level navigation that isn't routed
    // through us (back/forward). Cheap popstate listener.
    const onPop = () => {
      const next = roleFromPath(window.location.pathname);
      setRoleState((cur) => (cur === next ? cur : next));
    };
    window.addEventListener('popstate', onPop);
    return () => window.removeEventListener('popstate', onPop);
  }, []);

  const value = useMemo(() => ({ role, setRole }), [role, setRole]);
  return <RoleContext.Provider value={value}>{children}</RoleContext.Provider>;
}

const ROLES: readonly Role[] = ['holder', 'custodian', 'recipient'] as const;

const TAB_CLASSES: Record<Role, { active: string; idle: string }> = {
  holder: {
    active:
      'bg-blue-500/15 text-blue-200 border border-blue-500/40',
    idle: 'text-blue-300/70 hover:text-blue-200 hover:bg-blue-500/10',
  },
  custodian: {
    active:
      'bg-amber-500/15 text-amber-200 border border-amber-500/40',
    idle: 'text-amber-300/70 hover:text-amber-200 hover:bg-amber-500/10',
  },
  recipient: {
    active:
      'bg-emerald-500/15 text-emerald-200 border border-emerald-500/40',
    idle: 'text-emerald-300/70 hover:text-emerald-200 hover:bg-emerald-500/10',
  },
};

export function RoleSwitcher({
  onSelect,
}: {
  /** Optional side-effect hook — useful for navigating after selection.
   *  When omitted, clicks only update role state + localStorage. */
  onSelect?: (r: Role, defaultRoute: string) => void;
} = {}) {
  const { role, setRole } = useRole();

  return (
    <div
      role="tablist"
      aria-label="Demo role"
      className="inline-flex items-center gap-1 p-1 rounded-full border border-slate-700/60 bg-slate-900/50"
    >
      {ROLES.map((r) => {
        const cls = TAB_CLASSES[r];
        const isActive = role === r;
        return (
          <button
            key={r}
            type="button"
            role="tab"
            aria-selected={isActive}
            onClick={() => {
              setRole(r);
              onSelect?.(r, ROLE_ROUTES[r]);
            }}
            className={`px-3 py-1 rounded-full text-xs font-mono uppercase tracking-wider transition-colors ${
              isActive ? cls.active : cls.idle
            }`}
          >
            {r}
          </button>
        );
      })}
    </div>
  );
}
