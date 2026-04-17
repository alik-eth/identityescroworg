import { useTranslation } from 'react-i18next';
import { PhaseCard } from '../components/PhaseCard';

export function RegisterScreen() {
  const { t } = useTranslation();
  return <PhaseCard step={4} total={4} accent="purple" title={t('register.heading')} />;
}
