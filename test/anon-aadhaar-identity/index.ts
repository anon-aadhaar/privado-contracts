import { ethers } from 'hardhat';
import {
  _nullifierSeed,
  AnonAadhaarBalanceCredentialIssuerDeployHelper
} from '../helpers/AnonAadhaarBalanceCredentialIssuerDeployHelper';
import { StateDeployHelper } from '../helpers/StateDeployHelper';
import { expect } from 'chai';
import { Claim } from '@iden3/js-iden3-core';
import { AnonAadhaarProof, PackedGroth16Proof } from '@anon-aadhaar/core';
import { generateAnonAadhaarProof } from '../helpers/generateAnonAadhaarProof';
import { bigIntsToString } from '../../scripts/utils';

const _userId = 1;

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

    const proof = await generateAnonAadhaarProof(_nullifierSeed, user1address);
    anonAadhaarProof = proof.anonAadhaarProof;
    packedGroth16Proof = proof.packedGroth16Proof;
  });

  describe('create identity', function () {
    it.only("validate identity's id", async function () {
      const tx = await identity.issueCredential(
        _userId,
        _nullifierSeed,
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
      const usersCredentials = await identity.getUserCredentialIds(_userId);
      const credential = await identity.getCredential(_userId, usersCredentials[0]);

      const credentialData = credential[0];
      expect(credentialData.id).to.be.equal(0);
      expect(credentialData.context)
        .to.be.an('array')
        .that.includes(
          'https://raw.githubusercontent.com/anon-aadhaar/privado-contracts/main/assets/anon-aadhaar.jsonld',
          'https://schema.iden3.io/core/jsonld/displayMethod.jsonld'
        );
      expect(credentialData._type).to.be.equal('AnonAadhaarCredential');
      expect(credentialData.credentialSchema.id).to.be.equal(
        'https://raw.githubusercontent.com/anon-aadhaar/privado-contracts/main/assets/anon-aadhaar.json'
      );
      expect(credentialData.credentialSchema['_type']).to.be.equal('JsonSchema2023');
      expect(credentialData.displayMethod.id).to.be.equal(
        'https://raw.githubusercontent.com/anon-aadhaar/privado-contracts/main/assets/anon-aadhaar-display-method.json'
      );
      expect(credentialData.displayMethod['_type']).to.be.equal('Iden3BasicDisplayMethodV1');

      const coreClaim = credential[1];
      expect(coreClaim).to.be.not.empty;

      const credentialSubject = credential[2];
      expect(credentialSubject).to.be.an('array').that.length(4);

      // ageAbove18 credential
      const ageAbove18Field = credentialSubject[0];
      expect(ageAbove18Field.key).to.be.equal('ageAbove18');
      expect(ageAbove18Field.value).to.be.equal(BigInt(1));

      // gender credential
      const genderField = credentialSubject[1];
      expect(genderField.key).to.be.equal('gender');
      expect(bigIntsToString([BigInt(genderField.value)])).to.be.equal('M');

      // pincode credential
      const pincodeField = credentialSubject[2];
      expect(pincodeField.key).to.be.equal('pincode');
      expect(pincodeField.value).to.be.equal(110051);

      // state credential
      const stateField = credentialSubject[3];
      expect(stateField.key).to.be.equal('state');
      expect(bigIntsToString([BigInt(stateField.value)])).to.be.equal('Delhi');

      const inputs: Array<string> = [];
      coreClaim.forEach((c) => {
        inputs.push(c.toString());
      });

      const claim = new Claim().unMarshalJson(JSON.stringify(inputs));
      const mtpProof = await identity.getClaimProof(claim.hIndex());
      expect(mtpProof.existence).to.be.true;

      await expect(
        identity.issueCredential(
          _userId,
          _nullifierSeed,
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
        )
      ).to.be.revertedWith('[AnonAadhaarCredentialIssuer]: Previous claim not expired.');
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
