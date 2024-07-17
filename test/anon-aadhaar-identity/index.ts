import { ethers } from 'hardhat';
import { AnonAadhaarBalanceCredentialIssuerDeployHelper } from '../helpers/AnonAadhaarBalanceCredentialIssuerDeployHelper';
import { StateDeployHelper } from '../helpers/StateDeployHelper';
import { expect } from 'chai';
import { Claim } from '@iden3/js-iden3-core';
import { AnonAadhaarProof, PackedGroth16Proof } from '@anon-aadhaar/core';
import { generateAnonAadhaarProof } from '../helpers/generateAnonAadhaarProof';

const nullifierSeed = 1234;

describe('Reproduce anon-aadhaar identity life cycle', function () {
  this.timeout(0);

  let identity;
  let anonAadhaarProof: AnonAadhaarProof;
  let packedGroth16Proof: PackedGroth16Proof;
  let user1address: string;

  before(async function () {
    const signer = await ethers.getImpersonatedSigner('0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266');

    const stDeployHelper = await StateDeployHelper.initialize([signer]);
    const deployHelper = await AnonAadhaarBalanceCredentialIssuerDeployHelper.initialize(
      [signer],
      true
    );
    const stContracts = await stDeployHelper.deployState();
    const contracts = await deployHelper.deployBalanceCredentialIssuer(
      stContracts.smtLib,
      stContracts.poseidon3,
      stContracts.poseidon4,
      await stContracts.state.getAddress()
    );
    identity = contracts.AnonAadhaarBalanceCredentialIssuer;

    // Using sender's address as signal
    const [user1] = await ethers.getSigners();
    user1address = user1.address;

    const proof = await generateAnonAadhaarProof(nullifierSeed, user1address);
    anonAadhaarProof = proof.anonAadhaarProof;
    packedGroth16Proof = proof.packedGroth16Proof;
  });

  describe('create identity', function () {
    it.only("validate identity's id", async function () {
      const tx = await identity.issueCredential(
        nullifierSeed,
        anonAadhaarProof.nullifier,
        anonAadhaarProof.timestamp,
        user1address,
        [
          anonAadhaarProof.ageAbove18,
          anonAadhaarProof.gender,
          anonAadhaarProof.pincode,
          anonAadhaarProof.state
        ],
        packedGroth16Proof
      );
      await tx.wait();
      const usersCredentials = await identity.getUserCredentialIds(anonAadhaarProof.nullifier);
      const credential = await identity.getCredential(
        anonAadhaarProof.nullifier,
        usersCredentials[0]
      );

      console.log('credential: ', credential);

      const credentialData = credential[0];
      expect(credentialData.id).to.be.equal(0);
      expect(credentialData.context)
        .to.be.an('array')
        .that.includes(
          'https://gist.githubusercontent.com/ilya-korotya/660496c859f8d31a7d2a92ca5e970967/raw/6b5fc14fe630c17bfa52e05e08fdc8394c5ea0ce/non-merklized-non-zero-balance.jsonld',
          'https://schema.iden3.io/core/jsonld/displayMethod.jsonld'
        );
      expect(credentialData._type).to.be.equal('Balance');
      expect(credentialData.credentialSchema.id).to.be.equal(
        'https://gist.githubusercontent.com/ilya-korotya/e10cd79a8cc26ab6e40400a11838617e/raw/575edc33d485e2a4c806baad97e21117f3c90a9f/non-merklized-non-zero-balance.json'
      );
      expect(credentialData.credentialSchema['_type']).to.be.equal('JsonSchema2023');
      expect(credentialData.displayMethod.id).to.be.equal(
        'ipfs://QmS8eY8ZCiAAW8qgx3T6SQ3HDGeddwLZsjPXNAZExQwRY4'
      );
      expect(credentialData.displayMethod['_type']).to.be.equal('Iden3BasicDisplayMethodV1');

      const coreClaim = credential[1];
      expect(coreClaim).to.be.not.empty;

      const credentialSubject = credential[2];
      expect(credentialSubject).to.be.an('array').that.length(2);

      const balanceField = credentialSubject[0];
      expect(balanceField.key).to.be.equal('balance');
      expect(balanceField.value).to.be.not.equal(0);

      const addressFiled = credentialSubject[1];
      expect(addressFiled.key).to.be.equal('address');
      const bigIntAddress = BigInt('0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266');
      expect(addressFiled.value).to.be.equal(bigIntAddress);

      const inputs: Array<string> = [];
      coreClaim.forEach((c) => {
        inputs.push(c.toString());
      });

      const claim = new Claim().unMarshalJson(JSON.stringify(inputs));
      console.log('Claim', claim);
      const mtpProof = await identity.getClaimProof(claim.hIndex());
      console.log('mtpProof', mtpProof);
      expect(mtpProof.existence).to.be.true;
    });
  });

  describe('check interface implementation', function () {
    it.only('EIP165 implementation', async function () {
      const isEIP165 = await identity.supportsInterface('0x01ffc9a7');
      expect(isEIP165).to.be.true;
    });
    it.only('check interface INonMerklizedIssuer implementation', async function () {
      const isINonMerklizedIssuer = await identity.supportsInterface('0x58874949');
      expect(isINonMerklizedIssuer).to.be.true;
    });
  });
});
