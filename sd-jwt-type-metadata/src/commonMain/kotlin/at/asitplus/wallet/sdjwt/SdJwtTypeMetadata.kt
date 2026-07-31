package at.asitplus.wallet.sdjwt

import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataDefinition.SerialNames
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class SdJwtTypeMetadata(
    @SerialName(SerialNames.VCT)
    val vct: SdJwtVcType,
    @SerialName(SerialNames.NAME)
    val name: String? = null,
    @SerialName(SerialNames.DESCRIPTION)
    val description: String? = null,
    @SerialName(SerialNames.DISPLAY)
    val display: SdJwtTypeMetadataTypeDisplayInformationList? = null,
    @SerialName(SerialNames.CLAIMS)
    val claims: SdJwtTypeMetadataClaimInformationList? = null,
    @SerialName(SerialNames.VCK)
    val vckExtensions: SdJwtTypeMetadataVckExtensions? = null,
)
