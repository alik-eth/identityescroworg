// Thin re-export façade over @qkb/sdk's witness module.
export {
  buildPhase2WitnessV4Draft,
  parseLeafPublicSignals,
  type BuildPhase2WitnessV4DraftInput,
  type LeafPublicSignals,
  type LeafWitnessInputV4,
  type Phase2SharedInputsV4,
  type Phase2WitnessV4,
} from '@qkb/sdk';
// witness-domain `leafPublicSignalsV4` projects a witness object into the
// 16-signal layout. The SDK also exports a registry-side helper of the
// same name; here we re-export the witness one under its canonical name.
export { leafPublicSignalsV4, type LeafPublicSignalsV4 } from '@qkb/sdk';
