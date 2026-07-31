package at.asitplus.wallet.sdjwt

import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable
data class SdJwtTypeMetadataVckExtensions(
    @SerialName(SerialNames.FORMAT)
    val format: CredentialFormatEnum,
    @SerialName(SerialNames.ISO_DOCTYPE)
    val isoDocType: String? = null,
    @SerialName(SerialNames.ISO_NAMESPACE)
    val isoNamespace: String? = null,
    @SerialName(SerialNames.VC_TYPE)
    val vcType: String? = null,
) {

    object SerialNames {
        const val ISO_DOCTYPE = "isoDocType"
        const val ISO_NAMESPACE = "isoNamespace"
        const val VC_TYPE = "vcType"
        const val FORMAT = "format"
    }

}

@Serializable(with = CredentialFormatEnum.Companion.Serializer::class)
enum class CredentialFormatEnum(val text: String) {
    JWT_VC("jwt_vc_json"),
    DC_SD_JWT("dc+sd-jwt"),
    MSO_MDOC("mso_mdoc");


    companion object {
        fun parse(text: String) = CredentialFormatEnum.entries.firstOrNull { it.text == text }

        object Serializer : KSerializer<CredentialFormatEnum> {

            override val descriptor: SerialDescriptor =
                PrimitiveSerialDescriptor("CredentialFormatEnumSerializer", PrimitiveKind.STRING)

            override fun serialize(encoder: Encoder, value: CredentialFormatEnum) {
                encoder.encodeString(value.text)
            }

            override fun deserialize(decoder: Decoder): CredentialFormatEnum {
                val text = decoder.decodeString()
                return CredentialFormatEnum.parse(text) ?: throw IllegalArgumentException(text)
            }
        }
    }
}
