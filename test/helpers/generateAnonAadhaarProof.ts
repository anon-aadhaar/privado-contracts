import {
  AnonAadhaarProof,
  ArtifactsOrigin,
  artifactUrls,
  generateArgs,
  init,
  InitArgs,
  PackedGroth16Proof,
  packGroth16Proof,
  prove
} from '@anon-aadhaar/core';
import fs from 'fs';
import { testQRData } from '../../assets/dataInput.json';

export async function generateAnonAadhaarProof(
  nullifierSeed: number,
  signal: string
): Promise<{
  anonAadhaarProof: AnonAadhaarProof;
  packedGroth16Proof: PackedGroth16Proof;
}> {
  const certificateDirName = __dirname + '/../../assets';
  const certificate = fs.readFileSync(certificateDirName + '/testCertificate.pem').toString();

  const anonAadhaarInitArgs: InitArgs = {
    wasmURL: artifactUrls.v2.wasm,
    zkeyURL: artifactUrls.v2.zkey,
    vkeyURL: artifactUrls.v2.vk,
    artifactsOrigin: ArtifactsOrigin.server
  };

  await init(anonAadhaarInitArgs);

  const args = await generateArgs({
    qrData: testQRData,
    certificateFile: certificate,
    nullifierSeed: nullifierSeed,
    signal: signal,
    fieldsToRevealArray: ['revealAgeAbove18', 'revealGender', 'revealPinCode', 'revealState']
  });

  const anonAadhaarCore = await prove(args);

  const anonAadhaarProof = anonAadhaarCore.proof;

  const packedGroth16Proof = packGroth16Proof(anonAadhaarProof.groth16Proof);

  return { anonAadhaarProof, packedGroth16Proof };
}
