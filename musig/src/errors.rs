#[derive(Debug, PartialEq)]
pub enum MusigError {
    InvalidPubkeyLength,
    NonceCommitmentNotGenerated,
    NoncePreCommitmentsNotReceived,
    NoncePreCommitmentsAndParticipantsNotMatch,
    NonceCommitmentsAndParticipantsNotMatch,
    SignatureShareAndParticipantsNotMatch,
    CommitmentIsNotInCorrectSubgroup,
    InvalidCommitment,
    InvalidPublicKey,
    InvalidParticipantPosition,
    NonceCommitmentsNotReceived,
    AggregatedNonceCommitmentNotComputed,
    ChallengeNotGenerated,
    InvalidSignatureShare,
}

impl MusigError {
    pub fn description(&self) -> &str {
        match *self {
            MusigError::InvalidPubkeyLength => "Public key length should be at least 1",
            MusigError::NonceCommitmentNotGenerated => "Nonce is not generated",
            MusigError::NoncePreCommitmentsNotReceived => "Other parties' pre-commitments are not received yet",
            MusigError::NoncePreCommitmentsAndParticipantsNotMatch => "Number of pre-commitments and participants does not match",
            MusigError::NonceCommitmentsNotReceived => "Other parties' commitment are not received yet",
            MusigError::NonceCommitmentsAndParticipantsNotMatch => "Number of commitments and participants does not match",
            MusigError::SignatureShareAndParticipantsNotMatch => "Number of signature share and participants does not match",
            MusigError::CommitmentIsNotInCorrectSubgroup => "Commitment is not in a correct subgroup",
            MusigError::InvalidCommitment => "Commitments does not match with hash",
            MusigError::InvalidPublicKey => "Invalid public key",
            MusigError::InvalidParticipantPosition => "Position of signer does not match with number of parties",            
            MusigError::AggregatedNonceCommitmentNotComputed => "Aggregated commitment is not computed",
            MusigError::ChallengeNotGenerated => "Challenge for fiat-shamir transform is not generated",
            MusigError::InvalidSignatureShare => "Signature is not verified",
        }
    }
}

impl std::error::Error for MusigError {}

impl std::fmt::Display for MusigError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.description())
    }
}