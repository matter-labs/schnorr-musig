use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum MusigError {
    #[error("Public key length should be at least 1")]
    InvalidPubkeyLength,
    #[error("Nonce is not generated")]
    NonceCommitmentNotGenerated,
    #[error("Other parties' pre-commitments are not received yet")]
    NoncePreCommitmentsNotReceived,
    #[error("Number of pre-commitments and participants does not match")]
    NoncePreCommitmentsAndParticipantsNotMatch,
    #[error("Other parties' commitment are not received yet")]
    NonceCommitmentsNotReceived,
    #[error("Number of commitments and participants does not match")]
    NonceCommitmentsAndParticipantsNotMatch,
    #[error("Number of signature share and participants does not match")]
    SignatureShareAndParticipantsNotMatch,
    #[error("Commitment is not in a correct subgroup")]
    CommitmentIsNotInCorrectSubgroup,
    #[error("Commitments does not match with hash")]
    InvalidCommitment,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Position of signer does not match with number of parties")]
    InvalidParticipantPosition,
    #[error("Aggregated commitment is not computed")]
    AggregatedNonceCommitmentNotComputed,
    #[error("Challenge for fiat-shamir transform is not generated")]
    ChallengeNotGenerated,
    #[error("Signature is not verified")]
    InvalidSignatureShare,
    #[error("Seed length must be 128 bytes")]
    InvalidSeed,
}
