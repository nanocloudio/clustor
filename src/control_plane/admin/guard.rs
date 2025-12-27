use crate::control_plane::core::CpGuardError;

use super::workflows_error::AdminError;

pub(crate) fn guard_result<T>(result: Result<T, CpGuardError>) -> Result<T, AdminError> {
    result.map_err(Into::into)
}
