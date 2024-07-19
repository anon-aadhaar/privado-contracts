import { keccak256, toUtf8Bytes, AbiCoder } from 'ethers';

// const inputString = 'anonaadhaar.storage.AnonAadhaarBalanceCredentialIssuer';
// const urlLD =
//   'https://raw.githubusercontent.com/anon-aadhaar/privado-contracts/main/assets/anon-aadhaar.jsonld';
// const schemaType = 'AnonAadhaarCredential';

export const getStorageHash = (inputStr: string) => {
  // Step 1: Compute keccak256 hash of the string input string e.g. "anonaadhaar.storage.AnonAadhaarBalanceCredentialIssuer"
  const hash1 = keccak256(toUtf8Bytes(inputStr));

  // Step 2: Interpret the result as a uint256 and subtract 1
  const uint256Value = BigInt(hash1) - BigInt(1);

  // Step 3: ABI-encode the resulting uint256 value
  const coder = new AbiCoder();
  const encodedValue = coder.encode(['uint256'], [uint256Value.toString()]);

  // Step 4: Compute the keccak256 hash of the ABI-encoded value
  const hash2 = keccak256(encodedValue);

  // Step 5: Perform a bitwise AND operation with the inverse of bytes32(uint256(0xff))
  const mask = BigInt('0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00');
  const result = BigInt(hash2) & mask;

  return '0x' + result.toString(16).padStart(64, '0');
};

// createSchemaHash computes schema hash from schemaID
export function createSchemaHash(urlLD: string, schemaType: string): string {
  const schemaID = new TextEncoder().encode(urlLD + '#' + schemaType);
  const hash = keccak256(schemaID);
  const hashBytes = new Uint8Array(Buffer.from(hash)); // Convert hex string to Uint8Array
  const sHash = hashBytes.slice(-16); // Get the last 16 bytes
  return Buffer.from(sHash).toString('hex'); // Convert to hex string
}

export function bigIntsToString(bigIntChunks: bigint[]) {
  return bigIntChunksToByteArray(bigIntChunks)
    .map((byte) => String.fromCharCode(byte))
    .join('');
}

function bigIntChunksToByteArray(bigIntChunks: bigint[], bytesPerChunk = 31) {
  const bytes: number[] = [];

  // Remove last chunks that are 0n
  const cleanChunks = bigIntChunks
    .reverse()
    .reduce((acc: bigint[], item) => (acc.length || item !== BigInt(0) ? [...acc, item] : []), [])
    .reverse();

  cleanChunks.forEach((bigInt, i) => {
    let byteCount = 0;

    while (bigInt > BigInt(0)) {
      bytes.unshift(Number(bigInt & BigInt(0xff)));
      bigInt >>= BigInt(8);
      byteCount++;
    }

    // Except for the last chunk, each chunk should be of size bytesPerChunk
    // This will add 0s that were removed during the conversion because they are LSB
    if (i < cleanChunks.length - 1) {
      if (byteCount < bytesPerChunk) {
        for (let j = 0; j < bytesPerChunk - byteCount; j++) {
          bytes.unshift(0);
        }
      }
    }
  });

  return bytes.reverse(); // reverse to convert big endian to little endian
}
