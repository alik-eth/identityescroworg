import { useTranslation } from 'react-i18next';
import { PhaseCard } from '../components/PhaseCard';

export function GenerateScreen() {
  const { t } = useTranslation();
  return (
    <PhaseCard step={1} total={4} accent="emerald" title={t('generate.heading')} />
  );
}
