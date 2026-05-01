# Landing Page — Truth + Positioning Amendment

> Amends `docs/superpowers/plans/2026-04-18-landing-page.md`. Date: 2026-04-19. Status: authoritative — supersedes §Task 1 in full, adds §Task 1a (comparison table), §Task 1b (credibility strip), §Task 1c (demo screencast in hero). All other tasks in the original plan (routes, components, redirects, tests) stand unchanged except where they reference the renamed i18n keys.

## Why

Review of the 2026-04-18 plan against reality surfaced eight problems:

1. **Phase-1 "shipped end-to-end on Sepolia" is not yet true.** Trusted-setup ceremony is still running locally; no Sepolia V3 deploy has happened. Publishing the current claim would be a truth-in-advertising failure.
2. **"Single contributor" is not true.** Team: Ira (legal/notarization), Dima (product), Yana (design), plus the lead. Framing must reflect that.
3. **No legal-agency headline.** ZKPassport, World ID, Human Passport all claim "proof of humanity". Our differentiator is **legal force under Art. 25(2) eIDAS** — that must be in the hero, not buried.
4. **Recovery framing is premature.** Hero promises "never lose access" while QIE Phase 2 is still stubbed (real Groth16 verifiers not deployed). Claim must match ship state.
5. **No comparison table.** The obvious visitor question — "how is this different from ZKPassport?" — goes unanswered.
6. **No credibility strip.** Longfellow zk primitives, ETSI TR 119 476, Sedlmeir/University of Bayreuth collaboration, Lean 4 formal-verification track — none of it is surfaced. These are exactly the signals EU regulators scan for.
7. **Demo-GIF unused.** A 30–60 s screencast of real Diia QES → zk-proof → Sepolia register is our strongest proof point and hardest-to-fake artifact. Current plan treats the demo as a CTA button.
8. **Single-register copy.** "Run the demo and tell me what broke" plays on Hacker News but misreads Mintsyfra / Sedlmeir / DG CONNECT. Two audiences need two registers.

Priorities if time-constrained:
- **(1) + (2) + (3) are truth-in-advertising** — MUST ship before any public launch.
- (4)–(8) are positioning — high-leverage but can iterate post-launch.

---

## Task 1 (REPLACES original Task 1): i18n strings — truth-corrected, legal-agency-led

**Files:**
- Modify: `packages/web/src/i18n/en.json`
- Modify: `packages/web/src/i18n/uk.json`

- [ ] **Step 1: Replace EN `landing` namespace**

```json
"landing": {
  "heroEyebrow": "Legally qualified. Recoverable. Zero-knowledge.",
  "heroTitle": "A wallet signature with the legal force of a hand-signed contract.",
  "heroSubtitle": "identityescrow binds an Ethereum wallet to your eIDAS-qualified electronic signature. Under Art. 25(2) eIDAS, what that wallet signs carries the same legal weight as wet ink across all 27 EU member states — plus the UK, Ukraine, and 34 other ETSI-aligned jurisdictions. Zero-knowledge: the proof discloses only your wallet address and a per-context person-nullifier; no PII leaves your browser.",
  "ctaLaunchDemo": "Try the demo",
  "ctaReadDocs": "Read the spec",
  "ctaGithub": "View on GitHub",

  "qkbHeading": "QKB — Qualified Key Binding",
  "qkbBody": "A browser-only zk-SNARK that binds a wallet key to a valid eIDAS-qualified electronic signature (CAdES / PAdES / XAdES). The proof discloses only: wallet address, context, declaration hash, signature algorithm, timestamp, and a person-level nullifier for Sybil resistance.",
  "qkbBullets": [
    "Works with any ETSI EN 319 412-1 QES — Дія, Szafir, D-Trust, DocuSign EU, CERTUM, …",
    "One human = one nullifier per context. Stable across certificate renewals and issuers.",
    "On-chain registry; groth16 verifier; non-upgradeable contracts."
  ],

  "qieHeading": "QIE — Qualified Identity Escrow",
  "qieBody": "A recovery layer for the case QKB cannot solve on its own: you lose the private key. Your recovery material is split via Shamir across a threshold of QTSP custodians. Releasing it requires either an authority attestation or a notary-assisted heir flow — never a single-party decision.",
  "qieBullets": [
    "Threshold secret-sharing over GF(2^256); hybrid X25519 + ML-KEM-768 KEM.",
    "Two release paths — authority arbitrator (regulator / court order) and notary-assisted heir.",
    "On-chain state machine: ACTIVE → RELEASE_PENDING → RELEASED, 48h cancellation window."
  ],

  "rolesHeading": "Three roles in the demo",
  "roleHolderTitle": "Holder",
  "roleHolderBody": "Generates a wallet key, signs a binding declaration with their QES, registers it on Sepolia, and deposits recovery material with a custodian set of their choice.",
  "roleCustodianTitle": "Custodian",
  "roleCustodianBody": "A QTSP-operated agent that stores one Shamir share and only releases it when the arbitrator contract unlocks for a specific recipient hybrid public key.",
  "roleRecipientTitle": "Recipient",
  "roleRecipientBody": "The person designated to recover the holder's identity — typically the holder themselves post key-rotation, or an heir acting under a notary-attested instrument.",

  "statusHeading": "Project status",
  "statusBody": "Phase 1 (QKB): circuits, contracts, and LOTL flattener complete; real Diia QES validates end-to-end locally; trusted-setup ceremony and Sepolia deploy in progress — see the GitHub milestones for live status. Phase 2 (QIE): design and MVP refinement frozen; protocol implementation in active development against stub verifiers. No production use yet. No token. No audit.",

  "comparisonHeading": "How this differs from proof-of-humanity stacks",
  "comparisonNote": "Every system here proves a human is behind a wallet. None of them except identityescrow produces on-chain actions with the legal force of a hand-signed contract.",
  "comparisonRows": [
    {
      "feature": "Proves one human per context (Sybil resistance)",
      "iescrow": "Yes — person-nullifier from ETSI-mandated subject serialNumber",
      "zkpassport": "Yes — passport-anchored nullifier",
      "worldid": "Yes — orb biometric",
      "humanpassport": "Partial — stack score (weighted)"
    },
    {
      "feature": "Actions carry legal force under Art. 25(2) eIDAS",
      "iescrow": "Yes — wallet-signed = QES-signed at the binding layer",
      "zkpassport": "No — passport identification only",
      "worldid": "No",
      "humanpassport": "No"
    },
    {
      "feature": "Recoverable after private-key loss",
      "iescrow": "Yes — threshold QTSP custodian recovery (QIE)",
      "zkpassport": "No — re-enroll with new passport scan",
      "worldid": "Partial — re-verify at orb",
      "humanpassport": "No"
    },
    {
      "feature": "Works across 27 EU + UK + UA + 34 ETSI-aligned states out of box",
      "iescrow": "Yes — ETSI EN 319 412-1 QES on day one",
      "zkpassport": "Yes — ICAO-compliant passports",
      "worldid": "Orb-dependent (partial availability)",
      "humanpassport": "Stack-dependent (varies)"
    },
    {
      "feature": "No PII touches the server",
      "iescrow": "Yes — browser-only zk proof",
      "zkpassport": "Yes — passport stays on device",
      "worldid": "Eye template hashed locally",
      "humanpassport": "Depends per stamp"
    }
  ],

  "credibilityHeading": "Standards + academic grounding",
  "credibilityBullets": [
    "eIDAS 910/2014 Art. 25(2) — QES equivalence with hand-signed contract",
    "ETSI EN 319 412-1 — subject serialNumber semantics for person-level nullifier",
    "ETSI TR 119 476 — zk-proof-of-QES reference architecture",
    "Longfellow — zk primitives (Circom, snarkjs, BN254 Poseidon)",
    "Sedlmeir et al. (University of Bayreuth) — DB-CRL revocation primitive, ongoing consultation",
    "Lean 4 formal-verification track — witness builder + circuit invariants (in progress)"
  ],

  "footerAbout": "Built in the open by a small team: Alik (protocol, contracts, circuits), Ira (legal + notarization), Dima (product), Yana (design). No venture funding. No token. No moat — only primitives.",
  "footerContactPromptTechnical": "If you have an eIDAS QES and 10 min: run the demo and tell us what broke. GitHub issues or alikvovk@icloud.com.",
  "footerContactPromptInstitutional": "Notaries, QTSPs, academic collaborators: write to alikvovk@icloud.com. We reply within 48h."
}
```

- [ ] **Step 2: Replace UK `landing` namespace**

```json
"landing": {
  "heroEyebrow": "Юридично кваліфіковано. Відновлювано. Нульове розкриття.",
  "heroTitle": "Підпис гаманця з юридичною силою власноручного підпису.",
  "heroSubtitle": "identityescrow привʼязує гаманець Ethereum до вашого кваліфікованого електронного підпису (КЕП, eIDAS QES). За ст. 25(2) eIDAS — все, що підписує цей гаманець, має ту саму юридичну силу, що й паперовий підпис у всіх 27 країнах ЄС, а також у Великій Британії, Україні та 34 інших юрисдикціях, сумісних з ETSI. Нульове розкриття: доказ видає лише адресу гаманця та per-context nullifier особи; жодна PII не залишає браузер.",
  "ctaLaunchDemo": "Запустити демо",
  "ctaReadDocs": "Специфікація",
  "ctaGithub": "GitHub",

  "qkbHeading": "QKB — Qualified Key Binding",
  "qkbBody": "Повністю браузерний zk-SNARK, який привʼязує ключ гаманця до чинного eIDAS-кваліфікованого електронного підпису (CAdES / PAdES / XAdES). Доказ розкриває лише: адресу гаманця, контекст, хеш декларації, алгоритм підпису, мітку часу, person-nullifier для захисту від Сивіл-атак.",
  "qkbBullets": [
    "Працює з будь-яким QES за ETSI EN 319 412-1 — Дія, Szafir, D-Trust, DocuSign EU, CERTUM, …",
    "Одна людина = один nullifier на контекст. Стабільний між переоформленнями сертифікатів та QTSP.",
    "On-chain реєстр; groth16-верифікатор; контракти не upgradeable."
  ],

  "qieHeading": "QIE — Qualified Identity Escrow",
  "qieBody": "Рівень відновлення для випадку, який QKB сам не розвʼязує: ви втратили приватний ключ. Матеріал відновлення розщеплюється за схемою Шаміра між пороговою групою QTSP-кастодіанів. Розблокування вимагає або атестації повноважного органу, або нотаріально засвідченого процесу для спадкоємця — ніколи не рішення однієї сторони.",
  "qieBullets": [
    "Порогове розщеплення секрету над GF(2^256); гібридний KEM X25519 + ML-KEM-768.",
    "Два шляхи розблокування — арбітр (регулятор / суд) та нотаріальна атестація спадкоємця.",
    "On-chain state-машина: ACTIVE → RELEASE_PENDING → RELEASED, вікно скасування 48 год."
  ],

  "rolesHeading": "Три ролі в демо",
  "roleHolderTitle": "Власник",
  "roleHolderBody": "Генерує ключ гаманця, підписує декларацію привʼязки своїм QES, реєструє її на Sepolia та депонує матеріал відновлення у вибраній ним групі кастодіанів.",
  "roleCustodianTitle": "Кастодіан",
  "roleCustodianBody": "Керований QTSP агент, який зберігає одну частку Шаміра і розкриває її лише коли контракт-арбітр розблоковує депозит для конкретного hybrid public key отримувача.",
  "roleRecipientTitle": "Отримувач",
  "roleRecipientBody": "Особа, уповноважена відновити ідентичність власника — зазвичай сам власник після ротації ключа або спадкоємець за нотаріально засвідченим інструментом.",

  "statusHeading": "Статус проєкту",
  "statusBody": "Phase 1 (QKB): схеми, контракти та LOTL flattener готові; реальний QES Дія валідується end-to-end локально; церемонія довіреного встановлення і Sepolia-деплой у процесі — актуальний статус у GitHub milestones. Phase 2 (QIE): дизайн і MVP-уточнення заморожено; протокол у активній розробці на stub-верифікаторах. Продакшну немає. Токена немає. Аудиту немає.",

  "comparisonHeading": "Відмінність від стеків proof-of-humanity",
  "comparisonNote": "Кожна з цих систем доводить, що за гаманцем стоїть людина. Жодна, крім identityescrow, не породжує on-chain дій із юридичною силою власноручного підпису.",
  "comparisonRows": [
    {
      "feature": "Доводить «одна людина на контекст» (Сивіл-захист)",
      "iescrow": "Так — person-nullifier з ETSI-мандатованого subject serialNumber",
      "zkpassport": "Так — nullifier з паспорта",
      "worldid": "Так — біометрія Orb",
      "humanpassport": "Частково — stack-score"
    },
    {
      "feature": "Дії мають юридичну силу за ст. 25(2) eIDAS",
      "iescrow": "Так — підпис гаманцем = QES-підпис на рівні привʼязки",
      "zkpassport": "Ні — лише ідентифікація",
      "worldid": "Ні",
      "humanpassport": "Ні"
    },
    {
      "feature": "Відновлюваність після втрати приватного ключа",
      "iescrow": "Так — порогове QTSP-custodian відновлення (QIE)",
      "zkpassport": "Ні — повторна реєстрація з новим паспортом",
      "worldid": "Частково — re-verify на Orb",
      "humanpassport": "Ні"
    },
    {
      "feature": "Працює в 27 ЄС + UK + UA + 34 ETSI-сумісних країнах з коробки",
      "iescrow": "Так — ETSI EN 319 412-1 QES з першого дня",
      "zkpassport": "Так — ICAO-паспорти",
      "worldid": "Залежить від Orb (часткова наявність)",
      "humanpassport": "Залежить від stamp-стеку"
    },
    {
      "feature": "PII не потрапляє на сервер",
      "iescrow": "Так — zk-proof повністю в браузері",
      "zkpassport": "Так — паспорт лишається на пристрої",
      "worldid": "Шаблон ока хешується локально",
      "humanpassport": "Залежить від stamp"
    }
  ],

  "credibilityHeading": "Стандарти та наукова база",
  "credibilityBullets": [
    "eIDAS 910/2014 ст. 25(2) — QES еквівалентний власноручному підпису",
    "ETSI EN 319 412-1 — семантика subject serialNumber для person-nullifier",
    "ETSI TR 119 476 — референсна архітектура zk-proof-of-QES",
    "Longfellow — zk-примітиви (Circom, snarkjs, BN254 Poseidon)",
    "Sedlmeir et al. (University of Bayreuth) — DB-CRL revocation primitive, поточна консультація",
    "Lean 4 формальна верифікація — witness builder + circuit invariants (у процесі)"
  ],

  "footerAbout": "Побудовано відкрито малою командою: Alik (протокол, контракти, схеми), Іра (legal + нотаріат), Діма (продукт), Яна (дизайн). Без венчурного капіталу. Без токена. Без захисту ринку — тільки примітиви.",
  "footerContactPromptTechnical": "Маєте eIDAS QES і 10 хв? Запустіть демо і напишіть, що зламалося. GitHub issues або alikvovk@icloud.com.",
  "footerContactPromptInstitutional": "Нотаріуси, QTSP, академічні колаборатори: alikvovk@icloud.com. Відповідаємо протягом 48 год."
}
```

- [ ] **Step 3: Verify + commit** — same as original Task 1 Step 3–4.

---

## Task 1a (NEW): Comparison table component

**Files:**
- Create: `packages/web/src/components/landing/ComparisonTable.tsx`
- Test: `packages/web/tests/unit/landing.comparison.test.tsx`

- [ ] **Step 1: Write failing test**

```tsx
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { ComparisonTable } from '../../src/components/landing/ComparisonTable';
import { I18nextProvider } from 'react-i18next';
import i18n from '../../src/i18n';

describe('ComparisonTable', () => {
  it('renders all comparison rows with iescrow highlighted', () => {
    render(
      <I18nextProvider i18n={i18n}>
        <ComparisonTable />
      </I18nextProvider>,
    );
    expect(screen.getByText(/Legally qualified/i)).toBeInTheDocument();
    const rows = screen.getAllByRole('row');
    expect(rows.length).toBeGreaterThanOrEqual(6); // header + 5 feature rows
    // iescrow column must be visually emphasized (col header marked)
    expect(screen.getByRole('columnheader', { name: /identityescrow/i })).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Implement**

```tsx
// packages/web/src/components/landing/ComparisonTable.tsx
import { useTranslation } from 'react-i18next';

export function ComparisonTable() {
  const { t } = useTranslation();
  const rows = t('landing.comparisonRows', { returnObjects: true }) as Array<{
    feature: string;
    iescrow: string;
    zkpassport: string;
    worldid: string;
    humanpassport: string;
  }>;

  return (
    <section className="py-16">
      <h2 className="text-2xl font-semibold">{t('landing.comparisonHeading')}</h2>
      <p className="text-sm text-zinc-600 mt-2 max-w-2xl">{t('landing.comparisonNote')}</p>
      <div className="mt-8 overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-zinc-200">
            <tr>
              <th className="pb-3 pr-6 font-medium"></th>
              <th className="pb-3 pr-6 font-semibold text-zinc-900 bg-zinc-50">identityescrow</th>
              <th className="pb-3 pr-6 font-medium text-zinc-600">ZKPassport</th>
              <th className="pb-3 pr-6 font-medium text-zinc-600">World ID</th>
              <th className="pb-3 font-medium text-zinc-600">Human Passport</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row, i) => (
              <tr key={i} className="border-b border-zinc-100">
                <td className="py-3 pr-6 font-medium">{row.feature}</td>
                <td className="py-3 pr-6 bg-zinc-50">{row.iescrow}</td>
                <td className="py-3 pr-6 text-zinc-600">{row.zkpassport}</td>
                <td className="py-3 pr-6 text-zinc-600">{row.worldid}</td>
                <td className="py-3 text-zinc-600">{row.humanpassport}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
```

- [ ] **Step 3: Mount in `LandingScreen`** — between the "three roles" block and the status block.

- [ ] **Step 4: Commit**

```
git add packages/web/src/components/landing/ComparisonTable.tsx \
        packages/web/tests/unit/landing.comparison.test.tsx \
        packages/web/src/routes/landing.tsx
git commit -m "web(landing): comparison table — QKB/QIE vs ZKPassport/World ID/Human Passport"
```

---

## Task 1b (NEW): Credibility strip

**Files:**
- Create: `packages/web/src/components/landing/CredibilityStrip.tsx`
- Test: `packages/web/tests/unit/landing.credibility.test.tsx`

- [ ] **Step 1: Implement** — six bullets from `landing.credibilityBullets`, rendered as a horizontal strip (desktop) / vertical list (mobile). Each bullet is just text — no logo assets (we don't have ETSI / Bayreuth logo rights to use).

```tsx
export function CredibilityStrip() {
  const { t } = useTranslation();
  const bullets = t('landing.credibilityBullets', { returnObjects: true }) as string[];
  return (
    <section className="py-10 border-y border-zinc-200 bg-zinc-50">
      <h2 className="text-sm uppercase tracking-widest text-zinc-500 mb-4">
        {t('landing.credibilityHeading')}
      </h2>
      <ul className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-x-6 gap-y-2 text-sm">
        {bullets.map((b, i) => (
          <li key={i} className="flex gap-2">
            <span className="text-zinc-400 shrink-0">—</span>
            <span>{b}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}
```

- [ ] **Step 2: Mount in `LandingScreen`** — immediately below the hero, BEFORE QKB/QIE explainers.

- [ ] **Step 3: Commit**

```
git commit -m "web(landing): credibility strip — eIDAS/ETSI/Longfellow/Sedlmeir/Lean 4"
```

---

## Task 1c (NEW): Demo screencast in hero

**Files:**
- Create: `packages/web/public/demo/qkb-register.mp4` + `qkb-register.webm` (user produces via OBS + ffmpeg; lead cannot record).
- Create: `packages/web/public/demo/qkb-register-poster.png` (first frame, 1280×720).
- Create: `packages/web/src/components/landing/HeroScreencast.tsx`

Recording spec (for the user to produce once — this is gate for the landing going live):

- Length: 30–60 s. Target 45 s.
- Content: real Diia .p7s upload at `/demo/sign` → zk-proof generation progress → register tx sent to Sepolia (or local anvil if Sepolia isn't live yet — annotate onscreen as "local preview") → success card. No cursor trails, no mouse jitter. Typed text crops edited out.
- Resolution: 1280×720, 30 fps. Encode both MP4 (H.264, CRF 23) and WebM (VP9, CRF 32).
- Poster: still frame from the "proof generation" phase — shows progress bar mid-stroke, most visually distinctive moment.

- [ ] **Step 1: Implement `HeroScreencast`**

```tsx
// packages/web/src/components/landing/HeroScreencast.tsx
export function HeroScreencast() {
  return (
    <div className="mt-8 rounded-lg overflow-hidden shadow-2xl ring-1 ring-zinc-900/10 bg-zinc-50 aspect-video max-w-2xl">
      <video
        autoPlay
        loop
        muted
        playsInline
        poster="/demo/qkb-register-poster.png"
        className="w-full h-full object-cover"
      >
        <source src="/demo/qkb-register.webm" type="video/webm" />
        <source src="/demo/qkb-register.mp4" type="video/mp4" />
      </video>
    </div>
  );
}
```

- [ ] **Step 2: Mount in hero, right of the CTAs** — on desktop, the screencast sits in a two-column layout with the hero copy on the left. On mobile, stacks below the CTAs.

- [ ] **Step 3: Verify `.mp4` + `.webm` filesize** — each should be <5 MB at 45 s. If over, re-encode with higher CRF or shorter clip.

- [ ] **Step 4: Commit**

```
git add packages/web/public/demo/qkb-register.{mp4,webm,-poster.png} \
        packages/web/src/components/landing/HeroScreencast.tsx \
        packages/web/src/routes/landing.tsx
git commit -m "web(landing): hero screencast (real Diia QES → zk-proof → register)"
```

---

## Priority gate for publication

Do NOT publish the landing to production until:

1. Task 1 (truth-corrected i18n) committed.
2. Task 1c screencast recorded and committed. No screencast = no launch.
3. Sepolia V3 deploy completed and the status section updated to link specific contract addresses + Etherscan.
4. At least Ira reviewed the legal-force claim in English + Ukrainian (Art. 25(2) equivalence framing is her domain; misphrasing here is a liability).

Tasks 1a + 1b are strongly desirable but can ship post-launch if absolutely necessary.

## Drop or rewrite

From the original plan, the following bullets are now false or misleading — drop or rewrite:

- `"heroEyebrow": "Qualified keys. Recoverable identity. Zero-knowledge."` → replaced.
- `"heroTitle": "Prove you're a real human behind the wallet ..."` → replaced. "Real human" framing is what everyone else says; our differentiator is legal force.
- `"statusBody": "Phase 1 (QKB) shipped end-to-end on Sepolia ..."` → replaced. Not yet true.
- `"footerAbout": "Built ... by a single contributor ..."` → replaced. Team framing.
- `"footerContactPrompt": "Run the demo and tell me what broke."` → split into Technical + Institutional.

Keep from the original plan: role explainer, QKB/QIE headings + bullets (unchanged), the CTA structure, all route-reshape tasks (Task 3–7 in the original plan). This amendment changes copy + adds two components + gates the deploy on a screencast; nothing structural.
