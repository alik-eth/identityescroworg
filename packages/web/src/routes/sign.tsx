import { useTranslation } from 'react-i18next';
import { PhaseCard } from '../components/PhaseCard';

export function SignScreen() {
  const { t } = useTranslation();
  return <PhaseCard step={2} total={4} accent="blue" title={t('sign.heading')} />;
}
