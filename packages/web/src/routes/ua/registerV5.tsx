import { useEffect, useState } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { DocumentFooter } from '../../components/DocumentFooter';
import { PaperGrain } from '../../components/PaperGrain';
import { Step1ConnectWallet } from '../../components/ua/v5/Step1ConnectWallet';
import { Step2GenerateBinding } from '../../components/ua/v5/Step2GenerateBinding';
import { Step3DiiaSign } from '../../components/ua/v5/Step3DiiaSign';
import { Step4ProveAndRegister } from '../../components/ua/v5/Step4ProveAndRegister';
import { StepIndicatorV5 } from '../../components/ua/v5/StepIndicatorV5';
import { assessDeviceCapability } from '../../lib/deviceGate';

type StepNumber = 1 | 2 | 3 | 4;
type GateState = 'pending' | 'ready' | 'denied';

export function RegisterV5Screen() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [step, setStep] = useState<StepNumber>(1);
  const [p7s, setP7s] = useState<Uint8Array | null>(null);
  // Device-capability gate (spec amendment 9c866ad). Runs BEFORE Step 1 is
  // shown so the user can't even start connecting a wallet on a device
  // that can't finish the proof. Out-of-gate → /ua/use-desktop.
  const [gate, setGate] = useState<GateState>('pending');

  useEffect(() => {
    let cancelled = false;
    assessDeviceCapability()
      .then((result) => {
        if (cancelled) return;
        if (result.kind === 'denied') {
          setGate('denied');
          void navigate({ to: '/ua/use-desktop' });
        } else {
          setGate('ready');
        }
      })
      .catch(() => {
        // Detection itself failed — be conservative and reroute. The user
        // can still get back via the ← back link on /ua/use-desktop.
        if (cancelled) return;
        setGate('denied');
        void navigate({ to: '/ua/use-desktop' });
      });
    return () => {
      cancelled = true;
    };
  }, [navigate]);

  if (gate !== 'ready') {
    // Render a minimal placeholder while the gate runs (typically <50ms).
    // Once denied, navigation kicks in and this component unmounts; until
    // then we don't want to flash Step 1.
    return (
      <main className="relative min-h-screen">
        <PaperGrain />
        <div className="doc-grid pt-24 relative z-10">
          <div />
          <div className="max-w-3xl" data-testid="v5-device-gate-pending" />
        </div>
      </main>
    );
  }

  return (
    <main className="relative min-h-screen">
      <PaperGrain />
      <div className="doc-grid pt-24 relative z-10">
        <div />
        <div className="max-w-3xl space-y-12">
          <header className="space-y-6">
            <h1 className="text-5xl leading-none" style={{ color: 'var(--ink)' }}>
              {t('registerV5.title')}
            </h1>
            <p className="text-base max-w-prose" style={{ color: 'var(--ink)' }}>
              {t('registerV5.lede')}
            </p>
            <StepIndicatorV5 current={step} />
          </header>
          <hr className="rule" />
          {step === 1 && <Step1ConnectWallet onAdvance={() => setStep(2)} />}
          {step === 2 && (
            <Step2GenerateBinding onAdvance={() => setStep(3)} onBack={() => setStep(1)} />
          )}
          {step === 3 && (
            <Step3DiiaSign
              onP7s={(bytes) => {
                setP7s(bytes);
                setStep(4);
              }}
              onBack={() => setStep(2)}
            />
          )}
          {step === 4 && p7s && (
            <Step4ProveAndRegister p7s={p7s} onBack={() => setStep(3)} />
          )}
        </div>
      </div>
      <DocumentFooter />
    </main>
  );
}
