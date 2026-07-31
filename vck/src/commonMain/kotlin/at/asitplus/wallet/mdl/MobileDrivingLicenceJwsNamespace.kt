package at.asitplus.wallet.mdl

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * JWS representation of a [MobileDrivingLicence].
 */
@Serializable
data class MobileDrivingLicenceJwsNamespace(
    @SerialName(MDL_NAMESPACE)
    val mdl: MobileDrivingLicence,
)