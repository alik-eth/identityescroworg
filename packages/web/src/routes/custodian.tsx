import { Outlet } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { RoleShell } from '../components/RoleShell';

/**
 * Layout for the /custodian/* role section. Wraps every sub-route in the
 * amber-palette RoleShell so the custodian's section is visually distinct
 * from the holder (blue) and recipient (emerald) flows.
 */
export function CustodianLayout() {
  const { t } = useTranslation();
  return (
    <RoleShell role="custodian" className="p-6">
      <header className="mb-6">
        <h1 className="text-2xl font-serif italic text-amber-200">
          {t('custodian.layout.title')}
        </h1>
        <p className="mt-1 text-sm text-amber-300/70">
          {t('custodian.layout.subtitle')}
        </p>
      </header>
      <Outlet />
    </RoleShell>
  );
}
