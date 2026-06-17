package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.catching
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.CredentialMetadataLookup
import at.asitplus.wallet.lib.data.CredentialMetadataRegistry
import at.asitplus.wallet.lib.data.ResolvedCredentialMetadata
import at.asitplus.wallet.sdjwt.DelegatingSdJwtTypeMetadataDocumentResolver
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataDocumentIntegrityChecker
import at.asitplus.wallet.sdjwt.SdJwtVcType
import at.asitplus.wallet.sdjwt.W3cSubresourceIntegrityMetadata
import io.ktor.client.HttpClient
import kotlinx.serialization.json.Json
import kotlin.time.Clock

/**
 * A [CredentialMetadataRegistry] that fetches metadata documents over HTTP, mirroring
 * [at.asitplus.wallet.lib.data.StaticCredentialMetadataRegistry] but with remote retrieval.
 *
 * This registry **owns** the `vct -> URL` mapping ([documentUrls]); the underlying
 * [KtorSdJwtTypeMetadataDocumentRetriever] is given only a lookup (`documentUrls::get`), so the mapping stays in the
 * registry, not in the retriever. The same URL is reused as the resolved scheme's `schemaUri`.
 *
 * [documentUrls] is intentionally minimal — fill it with the known `vct`/URL pairs. The map is shared with the
 * retriever, so later additions are picked up for both lookup and retrieval (incl. `extends` parents).
 *
 * Identifier resolution mirrors the static registry: an [aliases] entry wins; otherwise for [SD_JWT] the identifier is
 * the `vct` directly. Mapping a decoupled W3C `vcType` / ISO `docType` to its `vct` needs an [aliases] entry until
 * richer discovery is added.
 */
class RemoteCredentialMetadataRegistry(
    httpClient: HttpClient,
    clock: Clock,
    /** `vct` -> hosted document URL. Owned here; fill in the known pairs. */
    val documentUrls: MutableMap<SdJwtVcType, String> = mutableMapOf(),
    private val aliases: Map<CredentialMetadataLookup, SdJwtVcType> = emptyMap(),
    private val integrityMetadata: Map<SdJwtVcType, W3cSubresourceIntegrityMetadata> = emptyMap(),
    json: Json = Json.Default,
    integrityChecker: SdJwtTypeMetadataDocumentIntegrityChecker = SdJwtTypeMetadataDocumentIntegrityChecker.DEFAULT,
) : CredentialMetadataRegistry {

    private val resolver = DelegatingSdJwtTypeMetadataDocumentResolver(
        documentRetriever = KtorSdJwtTypeMetadataDocumentRetriever(
            httpClient = httpClient,
            clock = clock,
            locateUrl = documentUrls::get,
            json = json,
            integrityChecker = integrityChecker,
        ),
        integrityChecker = integrityChecker,
    )

    override suspend fun findEntry(
        identifier: String,
        representation: CredentialRepresentation,
    ): ResolvedCredentialMetadata? {
        val vct = aliases[CredentialMetadataLookup(representation, identifier)]
            ?: SdJwtVcType(identifier).takeIf { representation == SD_JWT && documentUrls.containsKey(it) }
            ?: return null
        val loadedFrom = documentUrls[vct] ?: return null
        // Return null on fetch/integrity failure so AttributeIndex can fall back to a fallback scheme.
        val metadata = catching { resolver.resolve(vct, integrityMetadata[vct]) }.getOrNull() ?: return null
        return ResolvedCredentialMetadata(
            metadata = metadata,
            loadedFrom = loadedFrom,
            aliases = aliases.entries.filter { it.value == vct }.map { it.key.identifier }.toSet(),
        )
    }
}
