import { useTranslation } from 'react-i18next';

export function GenerateScreen() {
  const { t } = useTranslation();
  return (
    <section>
      <h2>{t('generate.heading')}</h2>
    </section>
  );
}
