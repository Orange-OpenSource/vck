package at.asitplus.wallet.lib.oidc

import at.asitplus.openid.RequestParameters
import at.asitplus.signum.indispensable.josef.JwsCompactTyped

/**
 * Implementations need to verify the passed [at.asitplus.signum.indispensable.josef.JwsCompactTyped] and return its result
 */
fun interface RequestObjectJwsVerifier {
    suspend operator fun invoke(jws: JwsCompactTyped<RequestParameters>): Boolean
}