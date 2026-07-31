package at.asitplus.wallet.sdjwt

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class SdJwtTypeMetadataTypeDisplayInformation(
    /**
     * REQUIRED: A language tag as defined in Section 2 of [RFC5646](https://datatracker.ietf.org/doc/html/rfc5646).
     */
    @SerialName(SerialNames.LOCALE)
    val locale: Rfc5646LanguageTag,
    /**
     * REQUIRED: A human-readable name for the type, intended for end users.
     */
    @SerialName(SerialNames.NAME)
    val name: String,
    /**
     * OPTIONAL: A human-readable description for the type, intended for end users.
     */
    @SerialName(SerialNames.DESCRIPTION)
    val description: String? = null,
    /**
     * OPTIONAL: An object containing rendering information for the type, as described in
     * [Section 4.5.1](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-17.html#rendering-metadata).
     */
    @SerialName(SerialNames.RENDERING)
    val rendering: SdJwtTypeMetadataTypeDisplayInformationRenderingMetadata? = null,
) {
    object SerialNames {
        const val LOCALE = "locale"
        const val NAME = "name"
        const val DESCRIPTION = "description"
        const val RENDERING = "rendering"
    }
}