package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.FixedTimeClock
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.CredentialMetadataLookup
import at.asitplus.wallet.lib.data.IsoMdocCredentialScheme
import at.asitplus.wallet.lib.data.SdJwtCredentialScheme
import at.asitplus.wallet.lib.data.toCredentialScheme
import at.asitplus.wallet.sdjwt.SdJwtVcType
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.http.*

/**
 * Verifies that SD-JWT Type Metadata documents hosted in the `credentials-collection` repository resolve through
 * [RemoteCredentialMetadataRegistry]. The two JSON bodies below mirror `ehic.json` and `age-verification.json` from
 * that repository; the [MockEngine] serves them at their configured URLs so the test stays hermetic (no live network).
 */
val RemoteCredentialMetadataResolutionTest by matrixSuite {

    val base = "https://raw.githubusercontent.com/a-sit-plus/credentials-collection/main"
    val ehicUrl = "$base/ehic.json"
    val ageVerificationUrl = "$base/age-verification.json"

    val ehicVct = SdJwtVcType("urn:eudi:ehic:1")
    val ageVerificationVct = SdJwtVcType("eu.europa.ec.av.1")

    fun registry() = RemoteCredentialMetadataRegistry(
        httpClient = HttpClient(MockEngine { request ->
            when (request.url.toString()) {
                ehicUrl -> respond(
                    content = EHIC_JSON,
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.CacheControl, "max-age=60"),
                )

                ageVerificationUrl -> respond(
                    content = AGE_VERIFICATION_JSON,
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.CacheControl, "max-age=60"),
                )

                else -> respondError(HttpStatusCode.NotFound)
            }
        }),
        clock = FixedTimeClock(0),
        documentUrls = mutableMapOf(
            ehicVct to ehicUrl,
            ageVerificationVct to ageVerificationUrl,
        ),
        // ISO mDoc has no direct vct fallback, so the docType must be aliased to the document's vct.
        aliases = mapOf(
            CredentialMetadataLookup(ISO_MDOC, ageVerificationVct.string) to ageVerificationVct,
        ),
    )

    "EHIC SD-JWT metadata resolves remotely" {
        val entry = registry().findEntry(ehicVct.string, SD_JWT).shouldNotBeNull()
        entry.metadata.vct shouldBe ehicVct
        entry.loadedFrom shouldBe ehicUrl

        val scheme = entry.toCredentialScheme().shouldBeInstanceOf<SdJwtCredentialScheme>()
        scheme.sdJwtType shouldBe ehicVct.string
        scheme.schemaUri shouldBe ehicUrl
        // All 13 claims parsed, including the nested issuing_authority.* / authentic_source.* objects, all mandatory.
        scheme.claimDescriptions.size shouldBe 13
        scheme.claimDescriptions.count { it.mandatory == true } shouldBe 13
    }

    "Age verification ISO mDoc metadata resolves remotely through an alias" {
        val entry = registry().findEntry(ageVerificationVct.string, ISO_MDOC).shouldNotBeNull()
        entry.metadata.vct shouldBe ageVerificationVct
        entry.loadedFrom shouldBe ageVerificationUrl

        val scheme = entry.toCredentialScheme().shouldBeInstanceOf<IsoMdocCredentialScheme>()
        scheme.isoDocType shouldBe ageVerificationVct.string
        scheme.isoNamespace shouldBe ageVerificationVct.string
        scheme.schemaUri shouldBe ageVerificationUrl
        // 11 age-over predicates; only age_over_18 is mandatory.
        scheme.claimDescriptions.size shouldBe 11
        scheme.claimDescriptions.count { it.mandatory == true } shouldBe 1
    }

    "unknown vct does not resolve" {
        registry().findEntry("urn:eudi:unknown:1", SD_JWT).shouldBeNull()
    }
}

private val EHIC_JSON = """
{
  "vct": "urn:eudi:ehic:1",
  "name": "European Health Insurance Card (EHIC)",
  "description": "European Health Insurance Card, issued as an SD-JWT VC.",
  "vck": { "format": "dc+sd-jwt" },
  "claims": [
    { "path": ["issuing_country"], "mandatory": true, "sd": "allowed" },
    { "path": ["personal_administrative_number"], "mandatory": true, "sd": "allowed" },
    { "path": ["issuing_authority"], "mandatory": true, "sd": "allowed" },
    { "path": ["issuing_authority", "id"], "mandatory": true, "sd": "allowed" },
    { "path": ["issuing_authority", "name"], "mandatory": true, "sd": "allowed" },
    { "path": ["authentic_source"], "mandatory": true, "sd": "allowed" },
    { "path": ["authentic_source", "id"], "mandatory": true, "sd": "allowed" },
    { "path": ["authentic_source", "name"], "mandatory": true, "sd": "allowed" },
    { "path": ["document_number"], "mandatory": true, "sd": "allowed" },
    { "path": ["date_of_issuance"], "mandatory": true, "sd": "allowed" },
    { "path": ["date_of_expiry"], "mandatory": true, "sd": "allowed" },
    { "path": ["starting_date"], "mandatory": true, "sd": "allowed" },
    { "path": ["ending_date"], "mandatory": true, "sd": "allowed" }
  ]
}
""".trimIndent()

private val AGE_VERIFICATION_JSON = """
{
  "vct": "eu.europa.ec.av.1",
  "name": "Age Verification",
  "description": "Age verification attestation, issued as an ISO/IEC 18013-5 mdoc.",
  "vck": {
    "format": "mso_mdoc",
    "isoDocType": "eu.europa.ec.av.1",
    "isoNamespace": "eu.europa.ec.av.1"
  },
  "claims": [
    { "path": ["eu.europa.ec.av.1", "age_over_18"], "mandatory": true },
    { "path": ["eu.europa.ec.av.1", "age_over_12"] },
    { "path": ["eu.europa.ec.av.1", "age_over_13"] },
    { "path": ["eu.europa.ec.av.1", "age_over_14"] },
    { "path": ["eu.europa.ec.av.1", "age_over_16"] },
    { "path": ["eu.europa.ec.av.1", "age_over_21"] },
    { "path": ["eu.europa.ec.av.1", "age_over_25"] },
    { "path": ["eu.europa.ec.av.1", "age_over_60"] },
    { "path": ["eu.europa.ec.av.1", "age_over_62"] },
    { "path": ["eu.europa.ec.av.1", "age_over_65"] },
    { "path": ["eu.europa.ec.av.1", "age_over_68"] }
  ]
}
""".trimIndent()
