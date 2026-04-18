# Landing Page + Demo-Route Split — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the current 2-line hero at `/` with a real landing page that explains QKB and QIE to a first-time visitor, and move the interactive demo (QKB 4-step flow + QIE escrow flows + custodian UI) under a `/demo` prefix so the landing is cleanly separated from the working prototype.

**Architecture:** Pure TanStack Router reshape — rename existing route paths, add a new `IndexScreen` landing component, update in-app navigation (header stepper, internal `Link`s, role-switcher deep links). No changes to business logic, witness building, or on-chain calls. Landing is mostly static content driven by the existing i18n layer; we add EN + UK strings.

**Tech Stack:** TanStack Router (existing), React + Tailwind (existing), react-i18next (existing). No new dependencies.

**Worker:** `web-eng` (single worker, all tasks).

**Route map — before → after:**

| Before | After | Notes |
|---|---|---|
| `/` | `/` | **Rewritten** — now a landing page (hero, what-is-QKB, what-is-QIE, 3-role explainer, CTAs to demo + GitHub + docs). |
| `/generate` | `/demo/generate` | Step 1 of QKB demo. |
| `/sign` | `/demo/sign` | Step 2. |
| `/upload` | `/demo/upload` | Step 3. |
| `/register` | `/demo/register` | Step 4. |
| `/escrow/setup` | `/demo/escrow/setup` | QIE holder flow. |
| `/escrow/recover` | `/demo/escrow/recover` | QIE recipient flow. |
| `/escrow/notary` | `/demo/escrow/notary` | QIE notary attestation. |
| `/custodian` | `/demo/custodian` | Custodian index. |
| `/custodian/$agentId` | `/demo/custodian/$agentId` | Per-agent layout. |
| `/custodian/$agentId/inbox` | `/demo/custodian/$agentId/inbox` | |
| `/custodian/$agentId/releases` | `/demo/custodian/$agentId/releases` | |
| `/custodian/$agentId/keys` | `/demo/custodian/$agentId/keys` | |

**Navigation behaviour:**
- Landing (`/`) shows a minimal header: logo-home, language switch, GitHub link, "Launch demo" CTA.
- Demo (`/demo/*`) shows the existing stepper + role switcher + language switch, same as today. No visible change for users already in-demo.

---

## Task 1: Add i18n strings for the landing page

**Files:**
- Modify: `packages/web/src/i18n/en.json`
- Modify: `packages/web/src/i18n/uk.json`

- [ ] **Step 1: Add EN strings under a new `landing` namespace**

Append to `packages/web/src/i18n/en.json` inside the top-level object:

```json
"landing": {
  "heroEyebrow": "Qualified keys. Recoverable identity. Zero-knowledge.",
  "heroTitle": "Prove you're a real human behind the wallet — and never lose access to your identity.",
  "heroSubtitle": "QKB binds a wallet key to your qualified electronic signature with a zk-SNARK. QIE splits the recovery material across threshold custodians so you can rotate keys without losing your on-chain history.",
  "ctaLaunchDemo": "Launch the demo",
  "ctaReadDocs": "Read the docs",
  "ctaGithub": "View on GitHub",
  "qkbHeading": "QKB — Qualified Key Binding",
  "qkbBody": "A browser-only zk-SNARK proof that a wallet key is controlled by the holder of a valid eIDAS-qualified electronic signature (CAdES / PAdES / XAdES). No PII leaves the browser — the proof discloses only the wallet address, context, declaration hash, algorithm, timestamp, and a person-level nullifier for Sybil resistance.",
  "qkbBullets": [
    "Works with any ETSI EN 319 412-1-compliant QES (Diia, Szafir, D-Trust, DocuSign EU, …).",
    "One person = one nullifier per context. Stable across certificate renewals.",
    "On-chain registry (Sepolia today, mainnet when audited). No off-chain trust."
  ],
  "qieHeading": "QIE — Qualified Identity Escrow",
  "qieBody": "A recovery protocol for the one case QKB cannot solve on its own: what happens when you lose the private key. Your recovery material is split via Shamir over a threshold of QTSP custodians. Releasing it requires an authority attestation or a notary-assisted heir flow — never a single-party decision.",
  "qieBullets": [
    "Threshold secret sharing over GF(2^256) with hybrid X25519 + ML-KEM-768 KEM.",
    "Two release paths — authority arbitrator (regulator / court order) and notary-assisted heir attestation.",
    "State machine on-chain: ACTIVE → RELEASE_PENDING → RELEASED, with a 48h cancellation window."
  ],
  "rolesHeading": "Three roles in the demo",
  "roleHolderTitle": "Holder",
  "roleHolderBody": "Generates a wallet key, signs a binding declaration with their QES, registers it on Sepolia, and deposits recovery material with a custodian set of their choice.",
  "roleCustodianTitle": "Custodian",
  "roleCustodianBody": "A QTSP-operated agent that stores one Shamir share and only releases it when the arbitrator contract unlocks for a specific recipient hybrid public key.",
  "roleRecipientTitle": "Recipient",
  "roleRecipientBody": "The person designated to recover the holder's identity — typically the holder themselves post key-rotation, or an heir acting under a notary-attested instrument.",
  "statusHeading": "Project status",
  "statusBody": "Phase 1 (QKB) shipped end-to-end on Sepolia with real Diia QES. Phase 2 (QIE) is in active development — the demo below exercises the full flow against stub verifiers until the trusted-setup ceremony completes.",
  "footerAbout": "Built in the open by a single contributor. No venture funding, no token, no moat — only the primitives.",
  "footerContactPrompt": "Have an eIDAS QES + 10 min? Run the demo and tell me what broke."
}
```

- [ ] **Step 2: Add UK strings**

Append to `packages/web/src/i18n/uk.json`:

```json
"landing": {
  "heroEyebrow": "Кваліфіковані ключі. Відновлювана ідентичність. Нульове розголошення.",
  "heroTitle": "Доведіть, що за гаманцем стоїть реальна людина — і ніколи не втрачайте доступ до своєї ідентичності.",
  "heroSubtitle": "QKB привʼязує ключ гаманця до вашого кваліфікованого електронного підпису через zk-SNARK. QIE розщеплює матеріал відновлення між пороговою групою кастодіанів — щоб ви могли ротувати ключі, не втрачаючи історію on-chain.",
  "ctaLaunchDemo": "Запустити демо",
  "ctaReadDocs": "Документація",
  "ctaGithub": "GitHub",
  "qkbHeading": "QKB — Qualified Key Binding",
  "qkbBody": "Повністю браузерний zk-SNARK, який доводить, що ключ гаманця контролюється власником чинного eIDAS-кваліфікованого електронного підпису (CAdES / PAdES / XAdES). Жодна PII не залишає браузер — доказ розкриває лише адресу гаманця, контекст, хеш декларації, алгоритм, мітку часу та нульовий ідентифікатор особи для захисту від Сивіл-атак.",
  "qkbBullets": [
    "Працює з будь-яким QES, сумісним з ETSI EN 319 412-1 (Дія, Szafir, D-Trust, DocuSign EU, …).",
    "Одна людина = один nullifier на контекст. Стабільний між переоформленнями сертифікатів.",
    "On-chain реєстр (Sepolia зараз, mainnet після аудиту). Жодної off-chain довіри."
  ],
  "qieHeading": "QIE — Qualified Identity Escrow",
  "qieBody": "Протокол відновлення для єдиного випадку, який QKB не розвʼязує сам: втрата приватного ключа. Матеріал відновлення розщеплюється за схемою Шаміра між пороговою групою кастодіанів-QTSP. Розблокування вимагає атестації повноважного органу або нотаріально засвідченого процесу для спадкоємця — ніколи не рішення однієї сторони.",
  "qieBullets": [
    "Порогове розщеплення секрету над GF(2^256) з гібридним KEM X25519 + ML-KEM-768.",
    "Два шляхи розблокування — арбітр (регулятор / рішення суду) та нотаріальна атестація спадкоємця.",
    "State-машина on-chain: ACTIVE → RELEASE_PENDING → RELEASED, з 48-годинним вікном скасування."
  ],
  "rolesHeading": "Три ролі в демо",
  "roleHolderTitle": "Власник",
  "roleHolderBody": "Генерує ключ гаманця, підписує декларацію привʼязки своїм QES, реєструє її на Sepolia та депонує матеріал відновлення у вибраній ним групі кастодіанів.",
  "roleCustodianTitle": "Кастодіан",
  "roleCustodianBody": "Керований QTSP агент, який зберігає одну частку Шаміра і розкриває її лише коли контракт-арбітр розблоковує депозит для конкретного hybrid public key отримувача.",
  "roleRecipientTitle": "Отримувач",
  "roleRecipientBody": "Особа, уповноважена відновити ідентичність власника — зазвичай сам власник після ротації ключа або спадкоємець за нотаріально засвідченим інструментом.",
  "statusHeading": "Статус проєкту",
  "statusBody": "Phase 1 (QKB) відвантажено end-to-end на Sepolia з реальним QES Дія. Phase 2 (QIE) — в активній розробці; демо нижче відпрацьовує повний потік на stub-верифікаторах до завершення церемонії довіреного встановлення.",
  "footerAbout": "Зроблено у відкритому доступі одним контриб’ютором. Без венчурного капіталу, без токена, без захисту ринку — тільки примітиви.",
  "footerContactPrompt": "Маєте eIDAS QES і 10 хвилин? Запустіть демо і розкажіть, що зламалося."
}
```

- [ ] **Step 3: Verify i18n loads**

Run:
```bash
pnpm -F @qkb/web typecheck
```
Expected: PASS. TypeScript should not complain about missing i18n keys.

- [ ] **Step 4: Commit**

```bash
git add packages/web/src/i18n/en.json packages/web/src/i18n/uk.json
git commit -m "web: add landing-page i18n strings (EN + UK)"
```

---

## Task 2: Build the `LandingScreen` component

**Files:**
- Create: `packages/web/src/routes/landing.tsx`
- Test: `packages/web/tests/unit/landing.test.tsx`

- [ ] **Step 1: Write failing test**

```tsx
// packages/web/tests/unit/landing.test.tsx
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { LandingScreen } from '../../src/routes/landing';
import { MemoryRouter } from '@tanstack/react-router';
import { I18nextProvider } from 'react-i18next';
import i18n from '../../src/i18n';

describe('LandingScreen', () => {
  it('renders the hero title and CTA to /demo', () => {
    render(
      <I18nextProvider i18n={i18n}>
        <MemoryRouter>
          <LandingScreen />
        </MemoryRouter>
      </I18nextProvider>,
    );
    expect(screen.getByRole('heading', { level: 1 })).toBeInTheDocument();
    const cta = screen.getByRole('link', { name: /launch the demo/i });
    expect(cta).toHaveAttribute('href', '/demo/generate');
  });

  it('renders QKB and QIE explainer sections', () => {
    render(
      <I18nextProvider i18n={i18n}>
        <MemoryRouter>
          <LandingScreen />
        </MemoryRouter>
      </I18nextProvider>,
    );
    expect(screen.getByText(/QKB — Qualified Key Binding/)).toBeInTheDocument();
    expect(screen.getByText(/QIE — Qualified Identity Escrow/)).toBeInTheDocument();
  });

  it('renders the three-role explainer', () => {
    render(
      <I18nextProvider i18n={i18n}>
        <MemoryRouter>
          <LandingScreen />
        </MemoryRouter>
      </I18nextProvider>,
    );
    expect(screen.getByText(/Holder/)).toBeInTheDocument();
    expect(screen.getByText(/Custodian/)).toBeInTheDocument();
    expect(screen.getByText(/Recipient/)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm -F @qkb/web test tests/unit/landing.test.tsx`
Expected: FAIL with "Cannot find module '../../src/routes/landing'".

- [ ] **Step 3: Implement `LandingScreen`**

```tsx
// packages/web/src/routes/landing.tsx
import { Link } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';

const GITHUB_URL = 'https://github.com/alik-eth/identityescroworg';
const DOCS_URL = 'https://github.com/alik-eth/identityescroworg#readme';

export function LandingScreen() {
  const { t } = useTranslation();
  const qkbBullets = t('landing.qkbBullets', { returnObjects: true }) as string[];
  const qieBullets = t('landing.qieBullets', { returnObjects: true }) as string[];

  return (
    <div className="space-y-24 animate-fade-in">
      {/* Hero */}
      <section className="hero-mesh rounded-2xl border border-slate-800/80 px-8 py-20 text-center">
        <p className="font-mono text-[11px] tracking-widest text-emerald-400/90 uppercase mb-6">
          {t('landing.heroEyebrow')}
        </p>
        <h1 className="font-serif italic text-5xl md:text-6xl text-slate-100 leading-tight max-w-3xl mx-auto">
          {t('landing.heroTitle')}
        </h1>
        <p className="mt-6 text-slate-400 max-w-2xl mx-auto text-lg">
          {t('landing.heroSubtitle')}
        </p>
        <div className="mt-10 flex flex-wrap gap-3 justify-center">
          <Link
            to="/demo/generate"
            className="px-6 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold rounded-lg transition-colors text-sm"
          >
            {t('landing.ctaLaunchDemo')}
          </Link>
          <a
            href={GITHUB_URL}
            target="_blank"
            rel="noreferrer noopener"
            className="px-6 py-2.5 border border-slate-700 hover:border-slate-500 text-slate-200 font-semibold rounded-lg transition-colors text-sm"
          >
            {t('landing.ctaGithub')}
          </a>
          <a
            href={DOCS_URL}
            target="_blank"
            rel="noreferrer noopener"
            className="px-6 py-2.5 border border-slate-700 hover:border-slate-500 text-slate-200 font-semibold rounded-lg transition-colors text-sm"
          >
            {t('landing.ctaReadDocs')}
          </a>
        </div>
      </section>

      {/* QKB */}
      <section className="grid md:grid-cols-[1fr_2fr] gap-8 items-start">
        <h2 className="font-serif italic text-3xl text-slate-100">
          {t('landing.qkbHeading')}
        </h2>
        <div>
          <p className="text-slate-300 leading-relaxed">{t('landing.qkbBody')}</p>
          <ul className="mt-6 space-y-2 text-sm text-slate-400">
            {qkbBullets.map((b) => (
              <li key={b} className="flex gap-2">
                <span className="text-emerald-400 font-mono">→</span>
                <span>{b}</span>
              </li>
            ))}
          </ul>
        </div>
      </section>

      {/* QIE */}
      <section className="grid md:grid-cols-[1fr_2fr] gap-8 items-start">
        <h2 className="font-serif italic text-3xl text-slate-100">
          {t('landing.qieHeading')}
        </h2>
        <div>
          <p className="text-slate-300 leading-relaxed">{t('landing.qieBody')}</p>
          <ul className="mt-6 space-y-2 text-sm text-slate-400">
            {qieBullets.map((b) => (
              <li key={b} className="flex gap-2">
                <span className="text-emerald-400 font-mono">→</span>
                <span>{b}</span>
              </li>
            ))}
          </ul>
        </div>
      </section>

      {/* Roles */}
      <section>
        <h2 className="font-serif italic text-3xl text-slate-100 mb-8">
          {t('landing.rolesHeading')}
        </h2>
        <div className="grid md:grid-cols-3 gap-6">
          {[
            { title: t('landing.roleHolderTitle'), body: t('landing.roleHolderBody'), tone: 'emerald' },
            { title: t('landing.roleCustodianTitle'), body: t('landing.roleCustodianBody'), tone: 'sky' },
            { title: t('landing.roleRecipientTitle'), body: t('landing.roleRecipientBody'), tone: 'amber' },
          ].map((r) => (
            <div
              key={r.title}
              className="rounded-xl border border-slate-800/80 bg-slate-900/50 p-6"
            >
              <h3 className={`font-mono text-xs tracking-widest uppercase mb-3 text-${r.tone}-400`}>
                {r.title}
              </h3>
              <p className="text-slate-300 text-sm leading-relaxed">{r.body}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Status */}
      <section className="rounded-2xl border border-slate-800/80 bg-slate-900/50 px-8 py-10 text-center">
        <h2 className="font-serif italic text-2xl text-slate-100 mb-4">
          {t('landing.statusHeading')}
        </h2>
        <p className="text-slate-400 max-w-2xl mx-auto">{t('landing.statusBody')}</p>
        <div className="mt-6">
          <Link
            to="/demo/generate"
            className="inline-block px-6 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold rounded-lg transition-colors text-sm"
          >
            {t('landing.ctaLaunchDemo')}
          </Link>
        </div>
      </section>
    </div>
  );
}
```

Note: the unsafe-classname concatenation (`text-${r.tone}-400`) will be JIT-purged by Tailwind unless those classes appear verbatim somewhere. Add a safelist comment at the top of the file or hardcode the three classname strings in the array literal to sidestep the issue:

```tsx
{ title: ..., body: ..., toneClass: 'text-emerald-400' },
{ title: ..., body: ..., toneClass: 'text-sky-400' },
{ title: ..., body: ..., toneClass: 'text-amber-400' },
```

...then use `className={`font-mono ... ${r.toneClass}`}`. Update the implementation accordingly.

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm -F @qkb/web test tests/unit/landing.test.tsx`
Expected: 3/3 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/web/src/routes/landing.tsx packages/web/tests/unit/landing.test.tsx
git commit -m "web: LandingScreen — hero + QKB/QIE explainers + role cards"
```

---

## Task 3: Extract the current `IndexScreen` into `DemoIndexScreen` (at `/demo`)

**Files:**
- Rename: `packages/web/src/routes/index.tsx` → `packages/web/src/routes/demo.index.tsx`
- Modify: the renamed file (rename exported function)

- [ ] **Step 1: Rename file and export**

```bash
git mv packages/web/src/routes/index.tsx packages/web/src/routes/demo.index.tsx
```

Edit `demo.index.tsx`:
- Rename `export function IndexScreen()` → `export function DemoIndexScreen()`.
- Change the CTA's `to="/generate"` → `to="/demo/generate"`.

- [ ] **Step 2: Commit**

```bash
git add packages/web/src/routes/demo.index.tsx
git commit -m "web: rename IndexScreen → DemoIndexScreen (moves to /demo)"
```

---

## Task 4: Update router — mount landing at `/`, mount demo under `/demo`

**Files:**
- Modify: `packages/web/src/router.tsx`

- [ ] **Step 1: Update imports and route definitions**

Replace the existing route-definition block (from `const indexRoute = ...` to the end of the custodian routes):

```tsx
// Before:
import { IndexScreen } from './routes/index';
// After:
import { LandingScreen } from './routes/landing';
import { DemoIndexScreen } from './routes/demo.index';
```

Route tree:

```tsx
const rootRoute = createRootRoute({ component: RootLayout });

// Landing at /
const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  component: LandingScreen,
});

// /demo parent layout (re-uses RootLayout — no separate demo layout component).
const demoRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/demo',
  // Outlet renders child routes. No dedicated component — we rely on RootLayout's Outlet.
  // TanStack requires a component; use a passthrough.
  component: () => <Outlet />,
});

const demoIndexRoute = createRoute({
  getParentRoute: () => demoRoute,
  path: '/',
  component: DemoIndexScreen,
});

const generateRoute = createRoute({
  getParentRoute: () => demoRoute,
  path: 'generate',
  component: GenerateScreen,
});

const signRoute = createRoute({
  getParentRoute: () => demoRoute,
  path: 'sign',
  component: SignScreen,
});

const uploadRoute = createRoute({
  getParentRoute: () => demoRoute,
  path: 'upload',
  component: UploadScreen,
});

const registerRoute = createRoute({
  getParentRoute: () => demoRoute,
  path: 'register',
  component: RegisterScreen,
});

const escrowSetupRoute = createRoute({
  getParentRoute: () => demoRoute,
  path: 'escrow/setup',
  component: EscrowSetupScreen,
});

const escrowRecoverRoute = createRoute({
  getParentRoute: () => demoRoute,
  path: 'escrow/recover',
  component: EscrowRecoverScreen,
});

const escrowNotaryRoute = createRoute({
  getParentRoute: () => demoRoute,
  path: 'escrow/notary',
  component: EscrowNotaryScreen,
});

const custodianRoute = createRoute({
  getParentRoute: () => demoRoute,
  path: 'custodian',
  component: CustodianLayout,
});

// ... custodian child routes unchanged except getParentRoute chain above ...
```

Update the `routeTree` assembly at the bottom:

```tsx
const routeTree = rootRoute.addChildren([
  indexRoute,
  demoRoute.addChildren([
    demoIndexRoute,
    generateRoute,
    signRoute,
    uploadRoute,
    registerRoute,
    escrowSetupRoute,
    escrowRecoverRoute,
    escrowNotaryRoute,
    custodianRoute.addChildren([
      custodianIndexRoute,
      custodianAgentRoute.addChildren([
        custodianAgentIndexRoute,
        custodianInboxRoute,
        custodianReleasesRoute,
        custodianKeysRoute,
      ]),
    ]),
  ]),
]);
```

- [ ] **Step 2: Update header stepper links from `/<step>` to `/demo/<step>`**

In the same file, update the STEPS constant:

```tsx
const STEPS = [
  { to: '/demo/generate', key: 'nav.generate' },
  { to: '/demo/sign', key: 'nav.sign' },
  { to: '/demo/upload', key: 'nav.upload' },
  { to: '/demo/register', key: 'nav.register' },
] as const;
```

- [ ] **Step 3: Conditionally hide the stepper on the landing route**

Inside `RootLayoutInner`, gate the stepper render on the current path. TanStack Router exposes `useMatches()`:

```tsx
import { Outlet, Link, useMatches } from '@tanstack/react-router';

// ... inside RootLayoutInner:
const matches = useMatches();
const inDemo = matches.some((m) => m.routeId.includes('/demo'));
```

Wrap the `<nav>` stepper in `{inDemo && ( ... )}`.

Also add a "Launch demo" CTA visible in the header only when NOT in demo (so the landing page has a clear way forward from the header):

```tsx
{!inDemo && (
  <Link
    to="/demo/generate"
    className="px-3 py-1.5 rounded-full bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-semibold transition-colors"
  >
    {t('landing.ctaLaunchDemo')}
  </Link>
)}
```

- [ ] **Step 4: Typecheck + build**

Run:
```bash
pnpm -F @qkb/web typecheck
pnpm -F @qkb/web build
```
Expected: both PASS. Fix any import paths that still reference `./routes/index`.

- [ ] **Step 5: Smoke-test locally**

```bash
pnpm -F @qkb/web dev
```
Visit:
- `http://localhost:5173/` — landing should render.
- Click "Launch the demo" — should navigate to `/demo/generate` with the stepper visible.
- Click each stepper link — should navigate within `/demo/*`.
- `http://localhost:5173/demo/custodian` — should render the custodian index.

- [ ] **Step 6: Commit**

```bash
git add packages/web/src/router.tsx
git commit -m "web: mount landing at /, move demo under /demo prefix"
```

---

## Task 5: Update internal `Link to=` references across components

**Files:**
- Grep: any `to="/generate"`, `to="/sign"`, `to="/upload"`, `to="/register"`, `to="/escrow/`, `to="/custodian` in:
  - `packages/web/src/components/**`
  - `packages/web/src/routes/**`
  - `packages/web/src/features/**`

- [ ] **Step 1: Find all affected call sites**

Run:
```bash
rg -n "to=\"/(generate|sign|upload|register|escrow|custodian)" packages/web/src
```
Capture the output. Every match needs `/demo/` prepended.

- [ ] **Step 2: Rewrite each match**

For each hit, replace:
- `to="/generate"` → `to="/demo/generate"`
- `to="/sign"` → `to="/demo/sign"`
- `to="/upload"` → `to="/demo/upload"`
- `to="/register"` → `to="/demo/register"`
- `to="/escrow/setup"` → `to="/demo/escrow/setup"`
- `to="/escrow/recover"` → `to="/demo/escrow/recover"`
- `to="/escrow/notary"` → `to="/demo/escrow/notary"`
- `to="/custodian"` → `to="/demo/custodian"`
- `to="/custodian/..."` → `to="/demo/custodian/..."`

Also check `navigate({ to: '/...' })` calls (TanStack's programmatic nav) with the same substitutions.

- [ ] **Step 3: Typecheck + build again**

Run:
```bash
pnpm -F @qkb/web typecheck
pnpm -F @qkb/web build
```
Expected: both PASS. TanStack Router generates a typed route tree; any stale route literal will surface as a type error.

- [ ] **Step 4: Re-run unit tests**

Run:
```bash
pnpm -F @qkb/web test
```
Expected: all PASS. If any test hardcodes the old route strings, update the test.

- [ ] **Step 5: Commit**

```bash
git add packages/web/src
git commit -m "web: update internal Link refs to /demo-prefixed routes"
```

---

## Task 6: Playwright smoke test for the new routes

**Files:**
- Create: `packages/web/tests/playwright/landing.spec.ts`

- [ ] **Step 1: Write Playwright test**

```ts
// packages/web/tests/playwright/landing.spec.ts
import { test, expect } from '@playwright/test';

test.describe('landing page', () => {
  test('loads landing at / and navigates to demo', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    await expect(page.getByText(/QKB — Qualified Key Binding/)).toBeVisible();
    await expect(page.getByText(/QIE — Qualified Identity Escrow/)).toBeVisible();

    await page.getByRole('link', { name: /launch the demo/i }).first().click();
    await expect(page).toHaveURL(/\/demo\/generate$/);
  });

  test('stepper is hidden on landing, visible in demo', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByRole('link', { name: /generate/i })).toHaveCount(1); // only hero CTA
    await page.goto('/demo/generate');
    // stepper shows 4 items
    await expect(page.getByRole('link', { name: /01 generate/i })).toBeVisible();
    await expect(page.getByRole('link', { name: /04 register/i })).toBeVisible();
  });

  test('legacy /generate returns a 404 or 301', async ({ page }) => {
    const resp = await page.goto('/generate', { waitUntil: 'networkidle' });
    // SPA 404.html fallback renders; we accept either a 404 or a redirect.
    // The test asserts we are NOT on a working demo page at the old URL.
    await expect(page).not.toHaveURL(/\/generate$/);
  });
});
```

- [ ] **Step 2: Run the Playwright suite locally**

```bash
pnpm -F @qkb/web playwright test landing.spec.ts
```
Expected: 3/3 PASS. If the third test fails because the SPA serves the landing page for `/generate` (SPA soft-404), adjust the assertion — the contract we actually care about is "user cannot accidentally use old bookmarks to land on a working demo step." Either redirect `/generate` → `/demo/generate` via a catch-all redirect route (simpler), or accept the soft-404.

- [ ] **Step 3: Commit**

```bash
git add packages/web/tests/playwright/landing.spec.ts
git commit -m "web: playwright — landing + /demo route split smoke coverage"
```

---

## Task 7 (optional): Add legacy-URL redirects

Decide whether to redirect old URLs or leave them as 404. If you have external links or previously shared bookmarks (e.g., in the README, in the changelog, in prior blog posts), ADD redirects.

**Files:**
- Modify: `packages/web/src/router.tsx`

- [ ] **Step 1: Add redirect routes**

TanStack Router supports `redirect()` in a route's `beforeLoad`. Add at the top of the route tree:

```tsx
import { redirect } from '@tanstack/react-router';

const legacyPaths = [
  ['generate', '/demo/generate'],
  ['sign', '/demo/sign'],
  ['upload', '/demo/upload'],
  ['register', '/demo/register'],
  ['escrow/setup', '/demo/escrow/setup'],
  ['escrow/recover', '/demo/escrow/recover'],
  ['escrow/notary', '/demo/escrow/notary'],
  ['custodian', '/demo/custodian'],
] as const;

const legacyRedirectRoutes = legacyPaths.map(([from, to]) =>
  createRoute({
    getParentRoute: () => rootRoute,
    path: from,
    beforeLoad: () => { throw redirect({ to, replace: true }); },
  }),
);
```

Add `legacyRedirectRoutes` to `routeTree.addChildren([...])`.

- [ ] **Step 2: Re-run Playwright**

The third test should now confirm `/generate` redirects to `/demo/generate`. Update the assertion accordingly:

```ts
test('legacy /generate redirects to /demo/generate', async ({ page }) => {
  await page.goto('/generate');
  await expect(page).toHaveURL(/\/demo\/generate$/);
});
```

- [ ] **Step 3: Commit**

```bash
git add packages/web/src/router.tsx packages/web/tests/playwright/landing.spec.ts
git commit -m "web: legacy-URL redirects /generate etc → /demo/*"
```

---

## Task 8: Update README + CHANGELOG

**Files:**
- Modify: `README.md` (repo root) — any links to `/generate`, `/sign`, etc. update to `/demo/generate`, etc.
- Modify: `CHANGELOG.md` — add an entry.

- [ ] **Step 1: Find and update links**

```bash
rg -n "identityescrow\.org/(generate|sign|upload|register|escrow|custodian)" README.md CHANGELOG.md docs/
```

Rewrite each to `/demo/...`.

- [ ] **Step 2: Add CHANGELOG entry**

Add to top of `CHANGELOG.md`:

```markdown
## [Unreleased]

### Changed
- **Landing page at `/`.** The root route now serves a product-introduction landing with QKB + QIE explainers, role cards, and CTAs to the demo. The interactive flow (previously at `/generate`, `/sign`, `/upload`, `/register`, `/escrow/*`, `/custodian/*`) has moved under the `/demo` prefix.
- Legacy URLs (`/generate`, `/sign`, …) now redirect to their `/demo/` equivalents.
- Stepper navigation in the header shows only within `/demo/*`.
```

- [ ] **Step 3: Commit**

```bash
git add README.md CHANGELOG.md
git commit -m "docs: landing-page + /demo route split — README + CHANGELOG"
```

---

## Task 9: Fly deploy + production smoke

**Files:** none (deploy only).

- [ ] **Step 1: Build + deploy**

From repo root:
```bash
fly deploy -c fly.web.toml
```

- [ ] **Step 2: Smoke-test production**

- `curl -I https://identityescrow.org/` → 200.
- `curl -I https://identityescrow.org/demo/generate` → 200.
- `curl -I https://identityescrow.org/generate` → 301/302 → `/demo/generate` (if Task 7 shipped) or 200 SPA-soft-404 (if not).

Open in a browser: landing loads, "Launch the demo" CTA goes to `/demo/generate`, stepper shows on demo pages.

- [ ] **Step 3: Sanity-check GitHub Pages build**

The Pages workflow (`.github/workflows/pages.yml`) should have auto-run on the merge. Visit `https://pages.identityescrow.org/` and verify the same behaviour.

---

## Risks + notes

| Risk | Trigger | Mitigation |
|---|---|---|
| Tailwind JIT purges `text-<tone>-400` dynamic classnames | Role cards render without color | Use hardcoded `toneClass` strings per Task 2 Step 3. |
| TanStack typed-route tree breaks on `to="/demo/..."` literals | Build fails | TanStack route-tree is generated from the route-tree config — adding new paths refreshes it automatically. Run `pnpm -F @qkb/web typecheck` after Task 4 and fix any `to=` that the compiler still rejects. |
| Programmatic `navigate({ to: '/...' })` missed by the grep | Runtime 404 inside demo flow | Grep for `navigate\(\{` and `\brouter\.navigate\(` on top of the `to="/..."` grep in Task 5 Step 1. |
| External inbound links break | Social posts / README / partners still link to `/generate` | Ship Task 7 redirects (low cost, covers the case). |
| i18n bundle grows | Adds ~200 lines per language | Negligible; SPA already inlines all locales. |
