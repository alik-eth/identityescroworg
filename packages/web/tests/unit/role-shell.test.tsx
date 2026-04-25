import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { RoleShell } from '../../src/components/RoleShell';
import {
  RoleSwitcher,
  RoleProvider,
  useRole,
  roleFromPath,
} from '../../src/components/RoleSwitcher';

describe('RoleShell', () => {
  it('renders with the custodian data attribute', () => {
    render(
      <RoleShell role="custodian">
        <div>inner</div>
      </RoleShell>,
    );
    const shell = screen.getByTestId('role-shell');
    expect(shell).toHaveAttribute('data-role', 'custodian');
    expect(screen.getByText('inner')).toBeInTheDocument();
  });

  it.each(['holder', 'custodian', 'recipient'] as const)(
    'applies the %s palette classes',
    (role) => {
      render(
        <RoleShell role={role}>
          <span>x</span>
        </RoleShell>,
      );
      const shell = screen.getByTestId('role-shell');
      expect(shell.getAttribute('data-role')).toBe(role);
    },
  );
});

describe('roleFromPath', () => {
  it('returns custodian for /custodian/*', () => {
    expect(roleFromPath('/custodian')).toBe('custodian');
    expect(roleFromPath('/custodian/agent-a/inbox')).toBe('custodian');
  });
  it('returns recipient for /escrow/notary and /escrow/recover', () => {
    expect(roleFromPath('/escrow/notary')).toBe('recipient');
    expect(roleFromPath('/escrow/recover')).toBe('recipient');
    expect(roleFromPath('/escrow/recover?mode=self')).toBe('recipient');
  });
  it('returns holder for /escrow/setup and the default step routes', () => {
    expect(roleFromPath('/escrow/setup')).toBe('holder');
    expect(roleFromPath('/ua/generate')).toBe('holder');
    expect(roleFromPath('/')).toBe('holder');
  });
});

describe('RoleSwitcher', () => {
  it('persists role selection in localStorage', () => {
    localStorage.clear();
    const Consumer = () => {
      const { role } = useRole();
      return <div data-testid="current-role">{role}</div>;
    };
    render(
      <RoleProvider initialRole="holder">
        <RoleSwitcher />
        <Consumer />
      </RoleProvider>,
    );
    expect(screen.getByTestId('current-role').textContent).toBe('holder');
    fireEvent.click(screen.getByRole('tab', { name: /custodian/i }));
    expect(screen.getByTestId('current-role').textContent).toBe('custodian');
    expect(localStorage.getItem('qie.demo.role')).toBe('custodian');
  });
});
