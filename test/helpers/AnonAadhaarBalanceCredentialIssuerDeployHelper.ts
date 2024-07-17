import { ethers, upgrades } from 'hardhat';
import { Contract } from 'ethers';
import { SignerWithAddress } from '@nomicfoundation/hardhat-ethers/signers';
import { deployClaimBuilder, deployIdentityLib } from '../utils/deploy-utils';

export const testPublicKeyHash =
  '15134874015316324267425466444584014077184337590635665158241104437045239495873';

export class AnonAadhaarBalanceCredentialIssuerDeployHelper {
  constructor(
    private signers: SignerWithAddress[],
    private readonly enableLogging: boolean = false
  ) {}

  static async initialize(
    signers: SignerWithAddress[] | null = null,
    enableLogging = false
  ): Promise<AnonAadhaarBalanceCredentialIssuerDeployHelper> {
    let sgrs;
    if (signers === null) {
      sgrs = await ethers.getSigners();
    } else {
      sgrs = signers;
    }
    return new AnonAadhaarBalanceCredentialIssuerDeployHelper(sgrs, enableLogging);
  }

  async deployBalanceCredentialIssuer(
    smtLib: Contract,
    poseidon3: Contract,
    poseidon4: Contract,
    stateContractAddress: string
  ): Promise<{
    AnonAadhaarBalanceCredentialIssuer: Contract;
  }> {
    const owner = this.signers[0];

    this.log('======== Balance credential issuer: deploy started ========');

    const cb = await deployClaimBuilder(true);
    const il = await deployIdentityLib(
      await smtLib.getAddress(),
      await poseidon3.getAddress(),
      await poseidon4.getAddress(),
      true
    );

    this.log('======== Balance credential issuer: deploy anon aadhaar contracts ========');
    const Verifier = await ethers.getContractFactory('Verifier');
    const verifier = await Verifier.deploy();

    const _verifierAddress = await verifier.getAddress();

    const pubkeyHashBigInt = BigInt(testPublicKeyHash).toString();

    const AnonAadhaarContract = await ethers.getContractFactory('AnonAadhaar');
    const anonAadhaarVerifier = await AnonAadhaarContract.deploy(
      _verifierAddress,
      pubkeyHashBigInt
    );

    const _AnonAadhaarAddress = await anonAadhaarVerifier.getAddress();

    const balanceCredentialIssuerFactory = await ethers.getContractFactory(
      'AnonAadhaarBalanceCredentialIssuer',
      {
        libraries: {
          ClaimBuilder: await cb.getAddress(),
          IdentityLib: await il.getAddress(),
          PoseidonUnit4L: await poseidon4.getAddress()
        }
      }
    );
    const AnonAadhaarBalanceCredentialIssuer = await upgrades.deployProxy(
      balanceCredentialIssuerFactory,
      [stateContractAddress, _AnonAadhaarAddress],
      {
        unsafeAllow: ['external-library-linking', 'struct-definition', 'state-variable-assignment'],
        initializer: 'initialize(address,address)'
      }
    );

    await AnonAadhaarBalanceCredentialIssuer.waitForDeployment();

    this.log(
      `BalanceCredentialIssuer contract deployed to address ${await AnonAadhaarBalanceCredentialIssuer.getAddress()} from ${await owner.getAddress()}`
    );

    this.log('======== Balance credential issuer: deploy completed ========');

    return {
      AnonAadhaarBalanceCredentialIssuer
    };
  }

  private log(...args): void {
    this.enableLogging && console.log(args);
  }
}
