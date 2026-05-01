import { Link } from '@tanstack/react-router';
import { DocumentFooter } from '../../components/DocumentFooter';
import { MintNftStep } from '../../components/ua/v5/MintNftStep';

/**
 * V5 mint route — post-register page reached after a successful
 * registerV5 transaction (Task 7 will navigate here on success).
 *
 * The page is also addressable directly: a registered user can revisit
 * `/ua/mintNft` later to mint at their leisure (mintDeadline allowing).
 */
export function MintNftScreen() {
  return (
    <main className="relative min-h-screen">
      <div className="doc-grid pt-12">
        <div className="text-mono text-xs pt-2 sticky top-12 self-start">
          <Link to="/" className="block mb-3">
            ← back
          </Link>
        </div>
        <div className="max-w-3xl">
          <MintNftStep />
        </div>
      </div>
      <DocumentFooter />
    </main>
  );
}
