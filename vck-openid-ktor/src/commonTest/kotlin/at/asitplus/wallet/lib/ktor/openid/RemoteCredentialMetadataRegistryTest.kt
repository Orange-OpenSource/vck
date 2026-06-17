package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.FixedTimeClock
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.CredentialMetadataLookup
import at.asitplus.wallet.sdjwt.SdJwtVcType
import com.benasher44.uuid.uuid4
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.http.*

val RemoteCredentialMetadataRegistryTest by matrixSuite {

    "findEntry fetches aliased remote metadata" {
        val vct = SdJwtVcType("urn:test:remote:${uuid4()}")
        val vcType = "RemoteTestCredential-${uuid4()}"
        val metadataUrl = "https://metadata.example.test/${uuid4()}/type-metadata.json"
        var requestedUrl: String? = null

        val httpClient = HttpClient(MockEngine { request ->
            requestedUrl = request.url.toString()
            respond(
                content = """
                    {
                      "vct": "${vct.string}",
                      "vck": {
                        "format": "jwt_vc_json",
                        "vcType": "$vcType"
                      }
                    }
                """.trimIndent(),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.CacheControl, "max-age=60")
            )
        })

        try {
            val registry = RemoteCredentialMetadataRegistry(
                httpClient = httpClient,
                clock = FixedTimeClock(0),
                documentUrls = mutableMapOf(vct to metadataUrl),
                aliases = mapOf(CredentialMetadataLookup(PLAIN_JWT, vcType) to vct),
            )

            val entry = registry.findEntry(vcType, PLAIN_JWT).shouldNotBeNull()

            requestedUrl shouldBe metadataUrl
            entry.loadedFrom shouldBe metadataUrl
            entry.metadata.vct shouldBe vct
            entry.metadata.vckExtensions?.vcType shouldBe vcType
            entry.aliases shouldContain vcType
        } finally {
            httpClient.close()
        }
    }

    "findEntry returns null when remote fetch fails" {
        val vct = SdJwtVcType("urn:test:remote:${uuid4()}")
        val metadataUrl = "https://metadata.example.test/${uuid4()}/type-metadata.json"

        val httpClient = HttpClient(MockEngine {
            respond(content = "", status = HttpStatusCode.InternalServerError)
        })

        try {
            val registry = RemoteCredentialMetadataRegistry(
                httpClient = httpClient,
                clock = FixedTimeClock(0),
                documentUrls = mutableMapOf(vct to metadataUrl),
            )

            registry.findEntry(vct.string, SD_JWT).shouldBeNull()
        } finally {
            httpClient.close()
        }
    }
}
