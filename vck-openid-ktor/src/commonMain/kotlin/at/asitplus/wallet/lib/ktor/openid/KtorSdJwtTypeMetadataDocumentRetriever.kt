package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.rfc3986uri.Rfc3986UniformResourceIdentifier
import at.asitplus.rfc3986uri.Rfc3986UriSchemeName
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataDefinition
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataDocument
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataDocumentIntegrityChecker
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataDocumentRetriever
import at.asitplus.wallet.sdjwt.SdJwtVcType
import at.asitplus.wallet.sdjwt.W3cSubresourceIntegrityMetadata
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.utils.CacheControl
import io.ktor.http.*
import kotlinx.serialization.json.Json
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

class KtorSdJwtTypeMetadataDocumentRetriever(
    val httpClient: HttpClient,
    val clock: Clock,
    /**
     * Resolves the URL a metadata document is hosted at for a given `vct` (used both as document identity and for
     * walking `extends`). Required because a `vct` is not necessarily a URL (e.g. `urn:eudi:pid:1`); the owning
     * [at.asitplus.wallet.lib.data.CredentialMetadataRegistry] keeps the actual `vct -> URL` mapping and supplies this
     * lookup. A `vct` for which this returns `null` cannot be fetched, and [retrieve] returns `null` for it.
     */
    val locateUrl: (SdJwtVcType) -> String?,
    val json: Json = Json.Default,
    val integrityChecker: SdJwtTypeMetadataDocumentIntegrityChecker = SdJwtTypeMetadataDocumentIntegrityChecker.DEFAULT,
) : SdJwtTypeMetadataDocumentRetriever {
    private val staticCache = mutableMapOf<SdJwtVcType, Pair<W3cSubresourceIntegrityMetadata, SdJwtTypeMetadataDocument>>()
    private val dynamicCache = mutableMapOf<SdJwtVcType, Pair<Instant, SdJwtTypeMetadataDocument>>()

    override suspend fun retrieve(
        sdJwtVcType: SdJwtVcType,
        integrityMetadata: W3cSubresourceIntegrityMetadata?,
    ): SdJwtTypeMetadataDocument? {
        val url = locateUrl(sdJwtVcType) ?: return null

        val uri = runCatching {
            Rfc3986UniformResourceIdentifier.Companion(url)
        }.getOrNull() ?: return null

        if (uri.schemeName !in Rfc3986UriSchemeName.Common.run { listOf(HTTPS, HTTP) }) {
            return null
        }

        if (integrityMetadata != null) {
            staticCache[sdJwtVcType]?.let { (integrity, document) ->
                if (integrityMetadata == integrity) {
                    return document
                }
                staticCache.remove(sdJwtVcType)
            }
        } else {
            dynamicCache[sdJwtVcType]?.let { (validUntil, document) ->
                if (clock.now() < validUntil) {
                    return document
                }
                dynamicCache.remove(sdJwtVcType)
            }
        }

        val response = httpClient.get(url)
        if (response.status == HttpStatusCode.OK) {
            val rawBytes = response.body<ByteArray>()
            val definition = json.decodeFromString(SdJwtTypeMetadataDefinition.serializer(), rawBytes.decodeToString())
            val document = SdJwtTypeMetadataDocument(originalBytes = rawBytes, definition = definition)
            if (integrityMetadata != null) {
                if (document.definition.vct != sdJwtVcType) return null
                integrityChecker.checkIntegrity(document, integrityMetadata)
                staticCache[sdJwtVcType] = integrityMetadata to document
            } else {
                if (document.definition.vct != sdJwtVcType) return null
                addToCache(
                    document = document,
                    sdJwtVcType = sdJwtVcType,
                    headers = response.headers
                )
            }
            return document
        }

        return null
    }

    /**
     * Otherwise, the Consumer MUST use the Cache-Control header of the HTTP response to determine how long the
     * metadata can be cached.
     */
    private fun addToCache(
        sdJwtVcType: SdJwtVcType,
        document: SdJwtTypeMetadataDocument,
        headers: Headers,
    ): Boolean {
        val cacheControlDirectives = headers[HttpHeaders.CacheControl]?.split(",")?.map {
            it.trim().lowercase()
        } ?: return false

        /**
         * public object CacheControl {
         *     public const val MAX_AGE: String = "max-age"
         *     public const val MIN_FRESH: String = "min-fresh"
         *     public const val ONLY_IF_CACHED: String = "only-if-cached"
         *
         *     public const val MAX_STALE: String = "max-stale"
         *     public const val NO_CACHE: String = "no-cache"
         *     public const val NO_STORE: String = "no-store"
         *     public const val NO_TRANSFORM: String = "no-transform"
         *
         *     public const val MUST_REVALIDATE: String = "must-revalidate"
         *     public const val PUBLIC: String = "public"
         *     public const val PRIVATE: String = "private"
         *     public const val PROXY_REVALIDATE: String = "proxy-revalidate"
         *     public const val S_MAX_AGE: String = "s-maxage"
         * }
         */
        val discouragingDirectives = listOf(
            CacheControl.NO_CACHE,
            CacheControl.NO_STORE,
            CacheControl.PRIVATE,
            CacheControl.MUST_REVALIDATE,
            CacheControl.PROXY_REVALIDATE,
            "must-understand", // TODO: check whether we understand all directives?
        )
        if (cacheControlDirectives.any { it in discouragingDirectives }) {
            return false
        }
        val maxAge = cacheControlDirectives.firstOrNull {
            it.startsWith("max-age=")
        }?.removePrefix("max-age=")?.let {
            try {
                it.toInt(10).coerceAtLeast(0)
            } catch (_: Throwable) {
                0
            }
        }
        if (maxAge == null) {
            return false
        }

        val age = headers[HttpHeaders.Age]?.let {
            try {
                it.toInt(10).coerceAtLeast(0)
            } catch (_: Throwable) {
                0
            }
        }
        val validUntil = clock.now() - (age?.seconds ?: Duration.ZERO) + maxAge.seconds
        dynamicCache[sdJwtVcType] = validUntil to document
        return true
    }
}
