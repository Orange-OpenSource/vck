package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.dif.ClaimFormat
import at.asitplus.iso.IssuerSigned
import at.asitplus.iso.sha256
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.IssuerMetadata
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.SupportedCredentialFormat
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT
import at.asitplus.wallet.lib.data.CredentialScheme
import at.asitplus.wallet.lib.data.IsoMdocFallbackCredentialScheme
import at.asitplus.wallet.lib.data.SdJwtFallbackCredentialScheme
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.UnknownCredentialScheme
import at.asitplus.wallet.lib.data.VcDataModelConstants.VERIFIABLE_CREDENTIAL
import at.asitplus.wallet.lib.data.VcFallbackCredentialScheme
import at.asitplus.wallet.lib.data.VerifiableCredential
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import io.ktor.utils.io.core.toByteArray
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToByteArray
import kotlin.String

/**
 * Stores all credentials that a subject has received
 */
interface SubjectCredentialStore {

    /**
     * Implementations should store the passed credential in a secure way.
     * Passed credentials have been validated before.
     *
     * @param vc Instance of [VerifiableCredentialJws]
     * @param vcSerialized Serialized form of [VerifiableCredential]
     */
    suspend fun storeCredential(
        vc: VerifiableCredentialJws,
        vcSerialized: String,
        scheme: CredentialScheme,
        renewalInfo: CredentialRenewalInfo? = null,
    ): StoreEntry

    /**
     * Implementations should store the passed credential in a secure way.
     * Passed credentials have been validated before.
     *
     * @param vc Instance of [VerifiableCredentialSdJwt]
     * @param vcSerialized Serialized form of [at.asitplus.wallet.lib.jws.SdJwtSigned]
     */
    suspend fun storeCredential(
        vc: VerifiableCredentialSdJwt,
        vcSerialized: String,
        disclosures: Map<String, SelectiveDisclosureItem?>,
        scheme: CredentialScheme,
        renewalInfo: CredentialRenewalInfo? = null,
    ): StoreEntry

    /**
     * Implementations should store the passed credential in a secure way.
     * Passed credentials have been validated before.
     *
     * @param issuerSigned Instance of [IssuerSigned] (an ISO credential)
     */
    suspend fun storeCredential(
        issuerSigned: IssuerSigned,
        scheme: CredentialScheme,
        renewalInfo: CredentialRenewalInfo? = null,
    ): StoreEntry

    /**
     * Return all stored credentials.
     * Selective Disclosure: Specify list of credential schemes in [credentialSchemes].
     */
    suspend fun getCredentials(credentialSchemes: Collection<CredentialScheme>? = null)
            : KmmResult<List<StoreEntry>>

    @Serializable
    sealed interface StoreEntry {
        val schemaUri: String
        val scheme: CredentialScheme
            get() = getFallbackScheme()
        val credentialFormat: CredentialFormatEnum
        val claimFormat: ClaimFormat
        val renewalInfo: CredentialRenewalInfo?

        fun getFallbackScheme(): CredentialScheme

        @Serializable
        data class Vc(
            @SerialName("vc-serialized")
            val vcSerialized: String,
            @SerialName("vc")
            val vc: VerifiableCredentialJws,
            @SerialName("schema-uri")
            override val schemaUri: String,
            @SerialName("credential-renewal-info")
            override val renewalInfo: CredentialRenewalInfo? = null,
        ) : StoreEntry {
            override fun getFallbackScheme(): CredentialScheme =
                vc.vc.type.firstOrNull { it != VERIFIABLE_CREDENTIAL }
                    ?.let { VcFallbackCredentialScheme(it) }
                    ?: UnknownCredentialScheme(PLAIN_JWT)

            override val credentialFormat: CredentialFormatEnum = CredentialFormatEnum.JWT_VC
            override val claimFormat: ClaimFormat = ClaimFormat.JWT_VP
        }

        @Serializable
        data class SdJwt(
            @SerialName("vc-serialized")
            val vcSerialized: String,
            @SerialName("sd-jwt")
            val sdJwt: VerifiableCredentialSdJwt,
            /** Map of serialized disclosure item (as [String]) to parsed item (as [SelectiveDisclosureItem]) */
            @SerialName("disclosures")
            val disclosures: Map<String, SelectiveDisclosureItem?>,
            @SerialName("schema-uri")
            override val schemaUri: String,
            @SerialName("credential-renewal-info")
            override val renewalInfo: CredentialRenewalInfo? = null,
        ) : StoreEntry {
            override fun getFallbackScheme(): CredentialScheme =
                SdJwtFallbackCredentialScheme(sdJwt.verifiableCredentialType)

            override val credentialFormat: CredentialFormatEnum = CredentialFormatEnum.DC_SD_JWT
            override val claimFormat: ClaimFormat = ClaimFormat.SD_JWT
        }

        @Serializable
        data class Iso(
            @SerialName("issuer-signed")
            val issuerSigned: IssuerSigned,
            @SerialName("schema-uri")
            override val schemaUri: String,
            @SerialName("credential-renewal-info")
            override val renewalInfo: CredentialRenewalInfo? = null,
        ) : StoreEntry {
            override fun getFallbackScheme(): CredentialScheme =
                issuerSigned.issuerAuth.payload?.docType?.let { IsoMdocFallbackCredentialScheme(it) }
                    ?: UnknownCredentialScheme(ISO_MDOC)

            override val credentialFormat: CredentialFormatEnum = CredentialFormatEnum.MSO_MDOC
            override val claimFormat: ClaimFormat = ClaimFormat.MSO_MDOC
        }

        @OptIn(ExperimentalStdlibApi::class)
        @Throws(IllegalArgumentException::class)
        fun getDcApiId(): String = when (this) {
            is Vc -> vc.jwtId
            is SdJwt -> sdJwt.jwtId
                ?: sdJwt.subject
                ?: joseCompliantSerializer.encodeToString(sdJwt).toByteArray().sha256().toHexString()

            is Iso -> coseCompliantSerializer.encodeToByteArray(issuerSigned).sha256().toHexString()
        }

    }
}

/**
 * Holds all information needed to refresh a credential, pass it to `OpenId4VciClient.refreshCredentialReturningResult`.
 */
@Serializable
data class CredentialRenewalInfo(
    /** Even if refresh token is not returned, other properties are used to initiate full re-issuance process */
    val refreshToken: String?,
    val issuerMetadata: IssuerMetadata,
    val oauthMetadata: OAuth2AuthorizationServerMetadata,
    val credentialFormat: SupportedCredentialFormat,
    val credentialIdentifier: String,
)
