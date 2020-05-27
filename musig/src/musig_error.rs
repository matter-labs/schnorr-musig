#[derive(Debug)]
pub enum MusigError {
    SelfIndexOutOfBounds,
    AssigningCommitmentToSelfIsForbidden,
    DuplicateCommitmentAssignment,
    AssigningRPubToSelfIsForbidden,
    AssigningRPubBeforeSettingAllCommitmentsIsForbidden,
    DuplicateRPubAssignment,
    RPubDoesntMatchWithCommitment,
    SigningBeforeSettingAllRPubIsForbidden,
    SigningShouldHappenOnlyOncePerSession,
    AggregatingSignatureBeforeSigningIsForbidden,
}

impl MusigError {
    pub fn description(&self) -> &str {
        match *self {
            MusigError::SelfIndexOutOfBounds => "self index is out of bounds",
            MusigError::AssigningCommitmentToSelfIsForbidden => {
                "assigning commitment to self is forbidden"
            }
            MusigError::DuplicateCommitmentAssignment => "duplicate commitment assignment",
            MusigError::AssigningRPubToSelfIsForbidden => "assigning r_pub to self is forbidden",
            MusigError::AssigningRPubBeforeSettingAllCommitmentsIsForbidden => {
                "assigning r_pub before setting all commitments is forbidden"
            }
            MusigError::DuplicateRPubAssignment => "duplicate r_pub assignment",
            MusigError::RPubDoesntMatchWithCommitment => "r_pub doesnt match with commitment",
            MusigError::SigningBeforeSettingAllRPubIsForbidden => {
                "signing before setting all r_pub is forbidden"
            }
            MusigError::SigningShouldHappenOnlyOncePerSession => {
                "signing should happen only once per session"
            }
            MusigError::AggregatingSignatureBeforeSigningIsForbidden => {
                "aggregating signature before signing is forbidden"
            }
        }
    }
}

impl std::error::Error for MusigError {}

impl std::fmt::Display for MusigError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.description())
    }
}
