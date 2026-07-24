package at.asitplus.wallet.lib.openid

import at.asitplus.openid.AuthenticationResponseParameters
import at.asitplus.wallet.lib.oidvci.OAuth2Error

/**
 * Intermediate DTO to hold the response to be sent from an [OpenId4VpHolder]
 * to an [OpenId4VpVerifier] or [DcApiVerifier].
 */
sealed class AuthenticationResponse {
    class Success(
        val params: AuthenticationResponseParameters,
    ) : AuthenticationResponse()

    class Error(
        val error: OAuth2Error,
    ) : AuthenticationResponse()
}