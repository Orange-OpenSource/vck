package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.sdjwt.CredentialFormatEnum
import at.asitplus.wallet.sdjwt.DelegatingSdJwtTypeMetadataDocumentResolver
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadata
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataDefinition
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataDocumentIntegrityChecker
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataDocumentRegistry
import at.asitplus.wallet.sdjwt.SdJwtVcType
import at.asitplus.wallet.sdjwt.W3cSubresourceIntegrityMetadata

/**
 * Static [CredentialMetadataRegistry] backed by an in-memory [SdJwtTypeMetadataDocumentRegistry].
 *
 * This is intended for libraries that ship known metadata documents in code. [documentUrls] provides the canonical
 * hosted URL for each entry document; that URL becomes [CredentialScheme.schemaUri] after resolution.
 */
class StaticCredentialMetadataRegistry(
    private val documentRegistry: SdJwtTypeMetadataDocumentRegistry,
    private val documentUrls: Map<SdJwtVcType, String>,
    private val aliases: Map<CredentialMetadataLookup, SdJwtVcType> = emptyMap(),
    private val integrityMetadata: Map<SdJwtVcType, W3cSubresourceIntegrityMetadata> = emptyMap(),
    integrityChecker: SdJwtTypeMetadataDocumentIntegrityChecker = SdJwtTypeMetadataDocumentIntegrityChecker.DEFAULT,
) : CredentialMetadataRegistry {

    private val resolver = DelegatingSdJwtTypeMetadataDocumentResolver(
        documentRetriever = documentRegistry,
        integrityChecker = integrityChecker,
    )

    /**
     * Self-contained bundled documents (those that don't `extends` another type) resolve synchronously, so they are
     * registered eagerly to pre-seed the synchronous lookups. Documents that extend another type are left to the
     * (suspending) [findEntry] path.
     */
    override fun preloadEntries(): Set<ResolvedCredentialMetadata> =
        documentRegistry.entries.mapNotNull { (vct, document) ->
            if (document.definition.extends != null) return@mapNotNull null
            resolvedMetadata(vct, document.definition.toSdJwtTypeMetadata())
        }.toSet()

    override suspend fun findEntry(
        identifier: String,
        representation: CredentialRepresentation,
    ): ResolvedCredentialMetadata? {
        val lookup = CredentialMetadataLookup(representation, identifier)
        val vct = aliases[lookup]
            ?: documentRegistry.entries.firstOrNull { (_, document) ->
                document.definition.matches(identifier, representation)
            }?.key
            ?: return null

        return resolvedMetadata(vct, resolver.resolve(vct, integrityMetadata[vct]))
    }

    private fun resolvedMetadata(vct: SdJwtVcType, metadata: SdJwtTypeMetadata): ResolvedCredentialMetadata {
        val loadedFrom = documentUrls[vct]
            ?: error("No metadata document URL configured for vct `$vct`.")
        return ResolvedCredentialMetadata(
            metadata = metadata,
            loadedFrom = loadedFrom,
            aliases = aliases.entries
                .filter { it.value == vct }
                .map { it.key.identifier }
                .toSet(),
        )
    }

    private fun SdJwtTypeMetadataDefinition.matches(
        identifier: String,
        representation: CredentialRepresentation,
    ): Boolean {
        val extensions = vckExtensions
        return when (representation) {
            PLAIN_JWT -> extensions?.format == CredentialFormatEnum.JWT_VC &&
                    extensions.vcType == identifier

            SD_JWT -> vct.string == identifier &&
                    (extensions?.format == null || extensions.format == CredentialFormatEnum.DC_SD_JWT)

            ISO_MDOC -> extensions?.format == CredentialFormatEnum.MSO_MDOC &&
                    extensions.isoDocType == identifier
        }
    }
}

data class CredentialMetadataLookup(
    val representation: CredentialRepresentation,
    val identifier: String,
)
