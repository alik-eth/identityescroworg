import { Link } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';

export function IndexScreen() {
  const { t } = useTranslation();
  return (
    <section>
      <h2>{t('index.heading')}</h2>
      <p>{t('index.subheading')}</p>
      <Link to="/generate">{t('index.start')}</Link>
    </section>
  );
}
