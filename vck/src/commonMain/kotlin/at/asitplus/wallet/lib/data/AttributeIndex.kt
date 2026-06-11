package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.data.AttributeIndex.resolveIdentifier
import at.asitplus.wallet.lib.data.AttributeIndex.resolveIdentifierPlainJwt
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.*
import at.asitplus.wallet.lib.data.VcDataModelConstants.VERIFIABLE_CREDENTIAL
import at.asitplus.wallet.lib.data.VcDataModelConstants.VERIFIABLE_PRESENTATION

object AttributeIndex {

    var credentialMetadataRegistrySet = setOf<CredentialMetadataRegistry>()
        private set

    var schemeSet = setOf<CredentialScheme>()
        private set

    init {
        schemeSet += ConstantIndex.AtomicAttribute2023
    }

    internal fun registerAttributeType(scheme: CredentialScheme) {
        schemeSet += scheme
    }

    internal fun registerCredentialMetadataRegistry(
        credentialMetadataRegistry: CredentialMetadataRegistry
    ) {
        credentialMetadataRegistrySet += credentialMetadataRegistry
        schemeSet += credentialMetadataRegistry.preloadEntries().map { it.toCredentialScheme() }
    }

    /**
     * Matches the passed [uri] against all known schemes from [CredentialScheme.schemaUri].
     */
    @Deprecated("Use other methods that resolve an identifier")
    fun resolveSchemaUri(uri: String): CredentialScheme? =
        schemeSet.firstOrNull { it.schemaUri == uri }

    /**
     * Matches the passed [type] against all known types from [CredentialScheme.vcType].
     *
     * External callers should prefer [resolveIdentifier] or [resolveIdentifierPlainJwt].
     */
    fun resolveAttributeType(type: String): CredentialScheme? =
        schemeSet.firstOrNull { it.vcType == type }

    /**
     * Matches the passed [sdJwtType] against all known types from [CredentialScheme.sdJwtType].
     *
     * External callers should prefer [resolveIdentifier].
     */
    fun resolveSdJwtAttributeType(sdJwtType: String): CredentialScheme? =
        schemeSet.firstOrNull { it.sdJwtType == sdJwtType }

    /**
     * Matches the passed [namespace] against all known namespace from [CredentialScheme.isoNamespace].
     *
     * Allows for extension to the namespace by appending ".countryname" or anything else, according to spec.
     *
     * External callers should prefer [resolveIdentifier].
     */
    fun resolveIsoNamespace(namespace: String): CredentialScheme? =
        schemeSet.filter { it.isoNamespace != null }
            .firstOrNull { it.isoNamespace!!.startsWith(namespace) || namespace.startsWith(it.isoNamespace!!) }

    /**
     * Matches the passed [docType] against all known docTypes from [CredentialScheme.isoDocType].
     *
     * Allows for extension to the namespace by appending ".countryname" or anything else, according to spec.
     *
     * External callers should prefer [resolveIdentifier].
     */
    fun resolveIsoDoctype(docType: String): CredentialScheme? =
        schemeSet.filter { it.isoDocType != null }
            .firstOrNull { it.isoDocType!!.startsWith(docType) || docType.startsWith(it.isoDocType!!) }

    /**
     * Given the [identifier] we try to resolve a [CredentialScheme],
     * with a "fallback scheme" as the last resort when the [identifier] is not registered with us.
     */
    suspend fun resolveIdentifier(
        identifier: String,
        representation: ConstantIndex.CredentialRepresentation
    ): CredentialScheme = when (representation) {
        PLAIN_JWT -> resolveAttributeType(identifier)
            ?: resolveAndRegister(identifier, representation)
            ?: VcFallbackCredentialScheme(vcType = identifier)

        SD_JWT -> resolveSdJwtAttributeType(identifier)
            ?: resolveAndRegister(identifier, representation)
            ?: SdJwtFallbackCredentialScheme(sdJwtType = identifier)

        ISO_MDOC -> resolveIsoDoctype(identifier)
            ?: resolveAndRegister(identifier, representation)
            ?: IsoMdocFallbackCredentialScheme(isoDocType = identifier)
    }

    private suspend fun resolveAndRegister(
        identifier: String,
        representation: ConstantIndex.CredentialRepresentation
    ): CredentialScheme? = credentialMetadataRegistrySet.firstNotNullOfOrNull {
        it.findEntry(identifier, representation)?.toCredentialScheme()
            ?.also { schemeSet += it }
    }

    /**
     * Given the collection of [identifiers] we try to resolve a [CredentialScheme],
     * assuming this is a list of `vcType` for [PLAIN_JWT] schemes. So we try to match the first one,
     * with a "fallback scheme" as the last resort when not one of the [identifiers] is not registered with us.
     */
    suspend fun resolveIdentifierPlainJwt(
        identifiers: Collection<String>,
    ): CredentialScheme = identifiers
        .filterNot { it == VERIFIABLE_CREDENTIAL }
        .filterNot { it == VERIFIABLE_PRESENTATION }.run {
            firstNotNullOfOrNull { resolveAttributeType(it) }
                ?: firstNotNullOfOrNull { resolveAndRegister(it, PLAIN_JWT) }
                ?: firstOrNull()?.let { VcFallbackCredentialScheme(vcType = it) }
        } ?: UnknownCredentialScheme(PLAIN_JWT)

}
