import { useTranslation } from 'react-i18next';

export function RegisterScreen() {
  const { t } = useTranslation();
  return (
    <section>
      <h2>{t('register.heading')}</h2>
    </section>
  );
}
