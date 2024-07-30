// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.20;

import {Ownable2StepUpgradeable} from '@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol';
import {ClaimBuilder} from '@iden3/contracts/lib/ClaimBuilder.sol';
import {IdentityLib} from '@iden3/contracts/lib/IdentityLib.sol';
import {INonMerklizedIssuer} from '@iden3/contracts/interfaces/INonMerklizedIssuer.sol';
import {NonMerklizedIssuerBase} from '@iden3/contracts/lib/NonMerklizedIssuerBase.sol';
import {PrimitiveTypeUtils} from '@iden3/contracts/lib/PrimitiveTypeUtils.sol';
import {PoseidonUnit4L} from '@iden3/contracts/lib/Poseidon.sol';
import {IAnonAadhaar} from '../interfaces/IAnonAadhaar.sol';

/**
 * @dev Example of decentralized balance credential issuer.
 * This issuer issue non-merklized credentials decentralized.
 */
contract AnonAadhaarBalanceCredentialIssuer is NonMerklizedIssuerBase, Ownable2StepUpgradeable {
    using IdentityLib for IdentityLib.Data;
    address public anonAadhaarVerifierAddr;

    /// @custom:storage-location erc7201:polygonid.storage.BalanceCredentialIssuer
    struct BalanceCredentialIssuerStorage {
        // countOfIssuedClaims count of issued claims for incrementing id and revocation nonce for new claims
        uint64 countOfIssuedClaims;
        // claim store
        mapping(uint256 => uint256[]) userClaims;
        mapping(uint256 => ClaimItem) idToClaim;
        mapping(uint256 => uint256) nullifierToUser;
        // this mapping is used to store credential subject fields
        // to escape additional copy in issueCredential function
        // since "Copying of type struct OnchainNonMerklizedIdentityBase.SubjectField memory[] memory to storage not yet supported."
        mapping(uint256 => INonMerklizedIssuer.SubjectField[]) idToCredentialSubject;
    }

    // keccak256(abi.encode(uint256(keccak256("anonaadhaar.storage.AnonAadhaarBalanceCredentialIssuer")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant BalanceCredentialIssuerStorageLocation =
        0x33009af875187a3bcbd4b4a66e5f861007d091075539980f2ae469e83db83e00;

    function _getBalanceCredentialIssuerStorage()
        private
        pure
        returns (BalanceCredentialIssuerStorage storage $)
    {
        assembly {
            $.slot := BalanceCredentialIssuerStorageLocation
        }
    }

    /**
     * @dev Version of contract
     */
    string public constant VERSION = '1.0.0';

    // jsonldSchemaHash hash of jsonld schema.
    // More about schema: https://devs.polygonid.com/docs/issuer-node/issuer-node-api/claim/apis/#get-claims
    uint256 private constant jsonldSchemaHash = 33373039626664303063323863343136;
    string private constant jsonSchema =
        'https://raw.githubusercontent.com/anon-aadhaar/privado-contracts/main/assets/anon-aadhaar.json';
    string private constant jsonldSchema =
        'https://raw.githubusercontent.com/anon-aadhaar/privado-contracts/main/assets/anon-aadhaar.jsonld';

    struct ClaimItem {
        uint256 id;
        uint64 issuanceDate;
        uint256[8] claim;
    }

    function initialize(address _stateContractAddr, address _verifierAddr) public initializer {
        require(anonAadhaarVerifierAddr == address(0), "Already initialized");
        anonAadhaarVerifierAddr = _verifierAddr;
        super.initialize(_stateContractAddr);
        __Ownable_init(_msgSender());
    }

    /**
     * @dev Get user's id list of credentials
     * @param _userId - user id
     * @return array of credential ids
     */
    function getUserCredentialIds(uint256 _userId) external view returns (uint256[] memory) {
        BalanceCredentialIssuerStorage storage $ = _getBalanceCredentialIssuerStorage();
        return $.userClaims[_userId];
    }

    /**
     * @dev Get credential by id
     * @param _userId - user id
     * @param _credentialId - credential id
     * @return credential data
     */
    function getCredential(
        uint256 _userId,
        uint256 _credentialId
    )
        external
        view
        override
        returns (
            INonMerklizedIssuer.CredentialData memory,
            uint256[8] memory,
            INonMerklizedIssuer.SubjectField[] memory
        )
    {
        BalanceCredentialIssuerStorage storage $ = _getBalanceCredentialIssuerStorage();

        string[] memory jsonLDContextUrls = new string[](2);
        jsonLDContextUrls[0] = jsonldSchema;
        jsonLDContextUrls[1] = 'https://schema.iden3.io/core/jsonld/displayMethod.jsonld';

        ClaimItem memory claimItem = $.idToClaim[_credentialId];
        INonMerklizedIssuer.CredentialData memory credentialData = INonMerklizedIssuer
            .CredentialData({
                id: claimItem.id,
                context: jsonLDContextUrls,
                _type: 'AnonAadhaarCredential',
                issuanceDate: claimItem.issuanceDate,
                credentialSchema: INonMerklizedIssuer.CredentialSchema({
                    id: jsonSchema,
                    _type: 'JsonSchema2023'
                }),
                displayMethod: INonMerklizedIssuer.DisplayMethod({
                    id: 'ipfs://QmS8eY8ZCiAAW8qgx3T6SQ3HDGeddwLZsjPXNAZExQwRY4',
                    _type: 'Iden3BasicDisplayMethodV1'
                })
            });
        return (credentialData, claimItem.claim, $.idToCredentialSubject[_credentialId]);
    }

    /**
     * @dev Revoke claim using it's revocationNonce
     * @param _revocationNonce  - revocation nonce
     */
    function revokeClaimAndTransit(uint64 _revocationNonce) public onlyOwner {
        _getIdentityBaseStorage().identity.revokeClaim(_revocationNonce);
        _getIdentityBaseStorage().identity.transitState();
    }

    /**
     * @dev Issue credential based on Anon Aadhaar Proof.
     * @param nullifierSeed: Nullifier Seed used while generating the proof.
     * @param nullifier: Nullifier for the user's Aadhaar data, used as user id for which the claim is issued.
     * @param timestamp: Timestamp of when the QR code was signed.
     * @param signal: signal used while generating the proof, should be equal to msg.sender.
     * @param revealArray: Array of the values used to reveal data, if value is 1 data is revealed, not if 0.
     * @param groth16Proof: SNARK Groth16 proof.
     */
    function issueCredential( 
        uint _userId,
        uint nullifierSeed,
        uint nullifier,
        uint timestamp,
        uint signal,
        uint[4] calldata revealArray, 
        uint[8] calldata groth16Proof) public {
        BalanceCredentialIssuerStorage storage $ = _getBalanceCredentialIssuerStorage();

        // Check if the nullifier has already been used
        uint256 userNullifier = $.nullifierToUser[nullifier];
        if (userNullifier != 0) {
            uint256[] memory previousClaims = $.userClaims[_userId];

            // Get the latest claim ID from the array
            uint256 latestClaimId = previousClaims[previousClaims.length - 1];
            ClaimItem memory latestClaim = $.idToClaim[latestClaimId];

            require(block.timestamp >= latestClaim.claim[4], "[AnonAadhaarCredentialIssuer]: Previous claim not expired.");
        }

        // require(
        //     isLessThan3HoursAgo(timestamp),
        //     '[AnonAadhaarVote]: Proof must be generated with Aadhaar data signed less than 3 hours ago.'
        // );
        require(
            IAnonAadhaar(anonAadhaarVerifierAddr).verifyAnonAadhaarProof(
                nullifierSeed, // nullifier seed
                nullifier,
                timestamp,
                signal,
                revealArray,
                groth16Proof
            ),
            '[AnonAadhaarBalanceCredentialIssuer]: The proof sent is not valid.'
        );
        require(revealArray[0] == 0 || revealArray[0] == 1, "[AnonAadhaarBalanceCredentialIssuer]: revealArray[0] must be 0 or 1");

        uint64 expirationDate = convertTime(block.timestamp + 30 days);

        ClaimBuilder.ClaimData memory claimData = ClaimBuilder.ClaimData({
            // metadata
            schemaHash: jsonldSchemaHash,
            idPosition: ClaimBuilder.ID_POSITION_INDEX,
            expirable: true,
            updatable: false,
            merklizedRootPosition: 0,
            version: 0,
            id: _userId,
            revocationNonce: $.countOfIssuedClaims,
            expirationDate: expirationDate,
            // data
            merklizedRoot: 0,
            indexDataSlotA = (revealArray[0] == 1),
            indexDataSlotB: revealArray[1],
            valueDataSlotA: revealArray[2],
            valueDataSlotB: revealArray[3]
        });
        uint256[8] memory claim = ClaimBuilder.build(claimData);

        uint256 hashIndex = PoseidonUnit4L.poseidon([claim[0], claim[1], claim[2], claim[3]]);
        uint256 hashValue = PoseidonUnit4L.poseidon([claim[4], claim[5], claim[6], claim[7]]);

        ClaimItem memory claimToSave = ClaimItem({
            id: $.countOfIssuedClaims,
            issuanceDate: convertTime(block.timestamp),
            claim: claim
        });

        $.idToCredentialSubject[$.countOfIssuedClaims].push(
            INonMerklizedIssuer.SubjectField({key: 'ageAbove18', value: revealArray[0], rawValue: ''})
        );
        $.idToCredentialSubject[$.countOfIssuedClaims].push(
            INonMerklizedIssuer.SubjectField({key: 'gender', value: revealArray[1], rawValue: ''})
        );
        $.idToCredentialSubject[$.countOfIssuedClaims].push(
            INonMerklizedIssuer.SubjectField({key: 'pincode', value: revealArray[2], rawValue: ''})
        );
        $.idToCredentialSubject[$.countOfIssuedClaims].push(
            INonMerklizedIssuer.SubjectField({key: 'state', value: revealArray[3], rawValue: ''})
        );

        $.nullifierToUser[nullifier] = _userId;
        addClaimHashAndTransit(hashIndex, hashValue);
        saveClaim(_userId, claimToSave);
    }

    // saveClaim save a claim to storage
    function saveClaim(uint256 _userId, ClaimItem memory _claim) private {
        BalanceCredentialIssuerStorage storage $ = _getBalanceCredentialIssuerStorage();

        $.userClaims[_userId].push($.countOfIssuedClaims);
        $.idToClaim[$.countOfIssuedClaims] = _claim;
        $.countOfIssuedClaims++;
    }

    // addClaimHashAndTransit add a claim to the identity and transit state
    function addClaimHashAndTransit(uint256 hashIndex, uint256 hashValue) private {
        _getIdentityBaseStorage().identity.addClaimHash(hashIndex, hashValue);
        _getIdentityBaseStorage().identity.transitState();
    }

    function convertTime(uint256 timestamp) private pure returns (uint64) {
        require(timestamp <= type(uint64).max, 'Timestamp exceeds uint64 range');
        return uint64(timestamp);
    }

    /// @dev Check if the timestamp is more recent than (current time - 3 hours)
    /// @param timestamp: msg.sender address.
    /// @return bool
    function isLessThan3HoursAgo(uint timestamp) public view returns (bool) {
        return timestamp > (block.timestamp - 3 hours);
    }
}
