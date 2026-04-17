import { useTranslation } from 'react-i18next';

export function SignScreen() {
  const { t } = useTranslation();
  return (
    <section>
      <h2>{t('sign.heading')}</h2>
    </section>
  );
}
