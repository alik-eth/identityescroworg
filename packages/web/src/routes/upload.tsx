import { useTranslation } from 'react-i18next';

export function UploadScreen() {
  const { t } = useTranslation();
  return (
    <section>
      <h2>{t('upload.heading')}</h2>
    </section>
  );
}
