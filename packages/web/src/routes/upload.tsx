import { useTranslation } from 'react-i18next';
import { PhaseCard } from '../components/PhaseCard';

export function UploadScreen() {
  const { t } = useTranslation();
  return <PhaseCard step={3} total={4} accent="amber" title={t('upload.heading')} />;
}
