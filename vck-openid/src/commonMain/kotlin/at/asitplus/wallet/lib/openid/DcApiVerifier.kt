package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.dcapi.DCAPIHandover
import at.asitplus.dcapi.DCAPIHandover.Companion.TYPE_DCAPI
import at.asitplus.dcapi.DCAPIInfo
import at.asitplus.dcapi.DigitalCredentialInterface
import at.asitplus.dcapi.IsoMdocResponse
import at.asitplus.dcapi.OpenID4VPDCAPIHandoverInfo
import at.asitplus.dcapi.OpenId4VpResponse
import at.asitplus.dcapi.SessionTranscriptContentHashable
import at.asitplus.dcapi.request.verifier.CredentialRequestOptions
import at.asitplus.dcapi.request.verifier.DigitalCredentialGetRequest
import at.asitplus.dif.ClaimFormat
import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.FormatContainerJwt
import at.asitplus.dif.FormatContainerSdJwt
import at.asitplus.dif.PresentationSubmissionDescriptor
import at.asitplus.iso.DeviceResponse
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.serializeOrigin
import at.asitplus.iso.sha256
import at.asitplus.jsonpath.JsonPath
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.IdTokenType
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.RelyingPartyMetadata
import at.asitplus.openid.ResponseParametersFrom
import at.asitplus.openid.SupportedAlgorithmsContainerIso
import at.asitplus.openid.SupportedAlgorithmsContainerJwt
import at.asitplus.openid.SupportedAlgorithmsContainerSdJwt
import at.asitplus.openid.TransactionDataBase64Url
import at.asitplus.openid.VpFormatsSupported
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.dcql.DCQLQueryResponse
import at.asitplus.rfc6749OAuth2AuthorizationFramework.ResponseType
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.cosef.toCoseAlgorithm
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JsonWebKeySet
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JweEncryption
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.signum.indispensable.josef.toJwsAlgorithm
import at.asitplus.wallet.lib.AbstractMdocVerifier
import at.asitplus.wallet.lib.DefaultNonceService
import at.asitplus.wallet.lib.NonceService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.NonceChallengeVerifier
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.agent.VerifierAgent
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureWithKey
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureWithKeyFun
import at.asitplus.wallet.lib.data.CredentialPresentationRequest.DCQLRequest
import at.asitplus.wallet.lib.data.CredentialPresentationRequest.PresentationExchangeRequest
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import at.asitplus.wallet.lib.data.toBase64UrlJsonString
import at.asitplus.wallet.lib.extensions.sessionTranscriptThumbprint
import at.asitplus.wallet.lib.jws.DecryptJwe
import at.asitplus.wallet.lib.jws.DecryptJweFun
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.SdJwtSigned
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import at.asitplus.wallet.lib.jws.VerifyJwsObjectFun
import at.asitplus.wallet.lib.procedures.dcql.DCQLQueryAdapter
import at.asitplus.wallet.lib.utils.DefaultMapStore
import at.asitplus.wallet.lib.utils.MapStore
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.coroutines.cancellation.CancellationException
import kotlin.jvm.JvmOverloads

/**
 * Implements a verifier for the [Digital Credentials API](https://www.w3.org/TR/digital-credentials/),
 * similar to [OpenId4VpVerifier] for OpenID4VP.
 *
 * This class creates the request for the Digital Credentials API in [createAuthnRequest]
 * (see [at.asitplus.dcapi.request.verifier.CredentialRequestOptions]), which the relying party's frontend
 * needs to pass to the browser (`navigator.credentials.get()`). The browser forwards it to the holder
 * (see [OpenId4VpHolder]), which will create the Authentication Response,
 * which will be verified here in [validateAuthnResponse].
 */
class DcApiVerifier @JvmOverloads constructor(
    /** Scheme to use for our client identifier. */
    private val clientIdScheme: ClientIdScheme,
    /** Key material to sign the authentication request with [signAuthnRequest]. */
    private val keyMaterial: KeyMaterial = EphemeralKeyWithoutCert(),
    /** Verifies the holder's response against our identifier from [clientIdScheme]. */
    val verifier: Verifier = VerifierAgent(identifier = clientIdScheme.clientId),
    /** Advertised in [metadata] so that holders can encrypt responses. */
    override val decryptionKeyMaterial: KeyMaterial = EphemeralKeyWithoutCert(),
    /** Decrypts encrypted responses from holders. */
    private val decryptJwe: DecryptJweFun = DecryptJwe(decryptionKeyMaterial),
    /** Signs authentication requests in [createSignedRequestObject]. */
    private val signAuthnRequest: SignJwtFun<AuthenticationRequestParameters> =
        SignJwt(keyMaterial, JwsHeaderClientIdScheme(clientIdScheme)),
    /** Validates signed responses from holders. */
    private val verifyJwsObject: VerifyJwsObjectFun = VerifyJwsObject(),
    /** Advertised in [metadata]. */
    private val supportedAlgorithms: Set<SignatureAlgorithm> = setOf(SignatureAlgorithm.ECDSAwithSHA256),
    /** Used to verify session transcripts from mDoc responses. */
    override val verifyCoseSignature: VerifyCoseSignatureWithKeyFun<ByteArray> = VerifyCoseSignatureWithKey(),
    /** Creates and validates OpenID4VP request nonces. */
    override val nonceService: NonceService = DefaultNonceService(),
    /** Used to store issued authn requests to verify the authn response to it */
    private val stateToAuthnRequestStore: MapStore<String, AuthenticationRequestParameters> = DefaultMapStore(),
    /** Algorithms supported to decrypt responses from wallets, for [metadataWithEncryption]. */
    private val supportedJweEncryptionAlgorithms: Set<JweEncryption> = JweEncryption.entries.toSet(),
) : AbstractMdocVerifier() {

    private val nonceAwareVerifier = NonceChallengeVerifier(
        verifierId = clientIdScheme.clientId,
        verifier = verifier,
        nonceService = nonceService,
    )
    private val supportedJwsAlgorithms = supportedAlgorithms
        .mapNotNull { it.toJwsAlgorithm().getOrNull()?.identifier }
    private val supportedCoseAlgorithms = supportedAlgorithms
        .mapNotNull { it.toCoseAlgorithm().getOrNull()?.coseValue }
    private val responseParser = ResponseParser(decryptJwe, verifyJwsObject)
    private val containerJwt = FormatContainerJwt(algorithmStrings = supportedJwsAlgorithms)
    private val containerSdJwt = FormatContainerSdJwt(
        sdJwtAlgorithmStrings = supportedJwsAlgorithms.toSet(),
        kbJwtAlgorithmStrings = supportedJwsAlgorithms.toSet()
    )

    /**
     * Creates the [at.asitplus.openid.RelyingPartyMetadata], without encryption (see [metadataWithEncryption])
     */
    val metadata by lazy {
        RelyingPartyMetadata(
            redirectUris = listOfNotNull((clientIdScheme as? ClientIdScheme.RedirectUri)?.redirectUri),
            jsonWebKeySet = JsonWebKeySet(
                listOf(
                    decryptionKeyMaterial.publicKey.toJsonWebKey(decryptionKeyMaterial.identifier).withAlgorithm()
                )
            ),
            vpFormatsSupported = VpFormatsSupported(
                vcJwt = SupportedAlgorithmsContainerJwt(
                    algorithmStrings = supportedJwsAlgorithms.toSet()
                ),
                dcSdJwt = SupportedAlgorithmsContainerSdJwt(
                    sdJwtAlgorithmStrings = supportedJwsAlgorithms.toSet(),
                    kbJwtAlgorithmStrings = supportedJwsAlgorithms.toSet(),
                ),
                msoMdoc = SupportedAlgorithmsContainerIso(
                    issuerAuthAlgorithmInts = supportedCoseAlgorithms.toSet(),
                    deviceAuthAlgorithmInts = supportedCoseAlgorithms.toSet(),
                ),
            )
        )
    }

    /**
     * Creates the [RelyingPartyMetadata], but with parameters set to request encryption of pushed authentication
     * responses, see [RelyingPartyMetadata.encryptedResponseEncValues].
     */
    val metadataWithEncryption by lazy {
        metadata.copy(
            encryptedResponseEncValuesSupportedString = supportedJweEncryptionAlgorithms.map { it.identifier }.toSet(),
            jsonWebKeySet = metadata.jsonWebKeySet?.let {
                JsonWebKeySet(it.keys.map { it.copy(publicKeyUse = "enc") })
            }
        )
    }

    /**
     * Creates a new authentication request for the W3C Digital Credentials API, i.e. the object that the
     * relying party's frontend needs to pass to the browser in `navigator.credentials.get()`.
     *
     * [requestOptions] must use [OpenIdConstants.ResponseMode.DcApi] or [OpenIdConstants.ResponseMode.DcApiJwt].
     */
    suspend fun createAuthnRequest(
        requestOptions: OpenId4VpRequestOptions,
        creationOptions: DcApiCreationOptions,
    ): KmmResult<CredentialRequestOptions> = catching {
        require(requestOptions.isAnyDcApi) {
            "responseMode must be ${OpenIdConstants.ResponseMode.DcApi} or ${OpenIdConstants.ResponseMode.DcApiJwt}"
        }
        CredentialRequestOptions.create(
            listOf(
                when (creationOptions) {
                    is DcApiCreationOptions.OpenId4VpUnsigned -> DigitalCredentialGetRequest.OpenId4VpUnsigned(
                        // client_id MUST be omitted in unsigned requests, per OpenID4VP 1.0 Appendix A.3.1
                        createPlainAuthnRequest(requestOptions.copy(populateClientId = false))
                    )

                    is DcApiCreationOptions.OpenId4VpSigned -> DigitalCredentialGetRequest.OpenId4VpSigned(
                        DigitalCredentialGetRequest.OpenId4Vp.SignedDataElement(
                            createSignedRequestObject(requestOptions).getOrThrow().jws
                        )
                    )
                }
            )
        )
    }

    private suspend fun createSignedRequestObject(
        requestOptions: OpenId4VpRequestOptions,
    ): KmmResult<JwsCompactTyped<AuthenticationRequestParameters>> = catching {
        val requestObject = createPlainAuthnRequest(requestOptions)
        val siopClientId = "https://self-issued.me/v2"
        val issuer = when (clientIdScheme) {
            is ClientIdScheme.PreRegistered -> clientIdScheme.issuerUri ?: clientIdScheme.clientId
            else -> siopClientId
        }
        signAuthnRequest(
            JwsContentTypeConstants.OAUTH_AUTHZ_REQUEST,
            requestObject.copy(
                audience = siopClientId,
                issuer = issuer,
            ),
            AuthenticationRequestParameters.serializer(),
        ).getOrThrow()
    }

    private suspend fun createPlainAuthnRequest(
        requestOptions: OpenId4VpRequestOptions,
    ) = requestOptions.toAuthnRequest()
        .also {
            storeAuthnRequest(it, requestOptions.state)
        }

    private suspend fun OpenId4VpRequestOptions.toAuthnRequest(): AuthenticationRequestParameters =
        AuthenticationRequestParameters(
            responseType = responseType,
            clientId = if (populateClientId) clientIdScheme.clientId else null,
            redirectUrl = if (!isAnyDirectPost) clientIdScheme.redirectUri else null,
            responseUrl = responseUrl,
            // Using scope as an alias for a well-defined Presentation Exchange or DCQL is not supported
            scope = if (isSiop) buildScope() else null,
            nonce = nonceAwareVerifier.provideNonce(),
            clientMetadata = clientMetadata(),
            idTokenType = if (isSiop) IdTokenType.SUBJECT_SIGNED.text else null,
            responseMode = responseMode,
            state = null,
            dcqlQuery = (presentationRequest as? DCQLRequest)?.dcqlQuery,
            presentationDefinition = (presentationRequest as? PresentationExchangeRequest)?.presentationDefinition?.run {
                copy(
                    inputDescriptors = inputDescriptors.map {
                        when (it) {
                            is DifInputDescriptor -> it.replaceAvailableFormatHolders()
                        }
                    }
                )
            },
            transactionData = transactionData?.map { it.toBase64UrlJsonString() },
            expectedOrigins = expectedOrigins,
        )

    /**
     * Defining *some* non-null format container is our way of specifying the allowed credential representations,
     * but provided values are overridden here
     */
    private fun DifInputDescriptor.replaceAvailableFormatHolders() = copy(
        format = format?.copy(
            jwtVp = format?.jwtVp?.let { containerJwt },
            sdJwt = format?.sdJwt?.let { containerSdJwt },
            msoMdoc = format?.msoMdoc?.let { containerJwt },
        )
    )

    private suspend fun storeAuthnRequest(
        authenticationRequestParameters: AuthenticationRequestParameters,
        externalId: String? = null,
    ) = stateToAuthnRequestStore.put(
        key = externalId
            ?: authenticationRequestParameters.state
            ?: throw IllegalArgumentException("Neither externalId nor state has been provided"),
        value = authenticationRequestParameters,
    )

    private fun OpenId4VpRequestOptions.clientMetadata(): RelyingPartyMetadata? = when (verifierMetadataMode) {
        VerifierMetadataMode.OMIT_IF_OUT_OF_BAND -> null
        VerifierMetadataMode.AUTO -> when (clientIdScheme) {
            is ClientIdScheme.RedirectUri,
            is ClientIdScheme.VerifierAttestation,
            is ClientIdScheme.CertificateSanDns,
            is ClientIdScheme.CertificateHash,
                -> if (responseMode.requiresEncryption) metadataWithEncryption else metadata

            else -> null
        }
    }

    /**
     * Validates an Authentication Response from the Wallet, where [input] is a signed or unsigned DC API response.
     *
     * The [externalId] will be used to load the corresponding [AuthenticationRequestParameters] from the store.
     */
    suspend fun validateAuthnResponse(
        input: String,
        externalId: String,
    ): KmmResult<AuthnResponseResult> = catching {
        validateAuthnResponse(
            input = joseCompliantSerializer.decodeFromString<DigitalCredentialInterface>(input),
            externalId = externalId
        ).getOrThrow()
    }

    /**
     * Validates an Authentication Response from the Wallet, where [input] is a signed or unsigned DC API response.
     *
     * The [externalId] will be used to load the corresponding [AuthenticationRequestParameters] from the store.
     */
    suspend fun validateAuthnResponse(
        input: DigitalCredentialInterface,
        externalId: String,
    ): KmmResult<AuthnResponseResult> = catching {
        when (input) {
            is IsoMdocResponse -> TODO()
            else -> validateAuthnResponse(
                input = responseParser.parseAuthnResponse(input as OpenId4VpResponse),
                externalId = externalId
            ).getOrThrow()
        }
    }

    /**
     * Validates an Authentication Response from the Wallet,
     * in case it has been parsed into [ResponseParametersFrom] with [ResponseParser].
     *
     * The [externalId] will be used to load the corresponding [AuthenticationRequestParameters] from the store,
     * in case a `state` parameter was not available in the request (e.g., when using DCAPI).
     */
    internal suspend fun validateAuthnResponse(
        input: ResponseParametersFrom,
        externalId: String
    ): KmmResult<AuthnResponseResult> = catching {
        Napier.d("validateAuthnResponse: $input")
        val authnRequest = loadAuthnRequest(input, externalId)

        val responseType = authnRequest.responseType?.let { ResponseType.Companion(it) }
        require(responseType != null) {
            "No response type was specified in the original authentication request."
        }
        require(OpenIdConstants.VP_TOKEN in responseType) {
            "Unsupported response type: $responseType"
        }
        val expectedNonce = authnRequest.nonce
            ?: throw IllegalArgumentException("nonce not present in $authnRequest")

        val vpTokenValidationResult = validateVpToken(authnRequest, input)

        AuthnResponseResult(
            idTokenValidationResult = null,
            vpTokenValidationResult = vpTokenValidationResult,
            request = authnRequest,
        ).also {
            if (it.isFullyValid()) {
                require(nonceAwareVerifier.verifyAndRemoveNonce(expectedNonce)) {
                    "nonce not valid: $expectedNonce, not known to us"
                }
            }
        }
    }

    private fun AuthnResponseResult.isFullyValid(): Boolean =
        idTokenValidationResult?.isFailure != true &&
                vpTokenValidationResult?.isFailure != true &&
                (vpTokenValidationResult?.getOrNull()?.isFullyValid() ?: true)

    private fun VpTokenValidationResult.isFullyValid(): Boolean =
        presentationResults.all { it.isSuccess } &&
                (this !is VpTokenValidationResultDCQL || submissionRequirementsValidationResult.isSuccess)

    @Throws(IllegalArgumentException::class, CancellationException::class)
    private suspend fun loadAuthnRequest(
        input: ResponseParametersFrom,
        externalId: String?,
    ): AuthenticationRequestParameters {
        val storedId = externalId
            ?: input.parameters.state
            ?: throw IllegalArgumentException("Neither externalId nor state given")
        val authnRequest = stateToAuthnRequestStore.get(storedId)
            ?: throw IllegalArgumentException("No authn request found for $storedId")
        if (authnRequest.responseMode?.requiresEncryption == true)
            require(input.hasBeenEncrypted) {
                "response_mode requires encryption, but no encrypted response was given"
            }
        return authnRequest
    }

    /**
     * Extract and verifies verifiable presentations, according to format defined in
     * [OpenID for VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html),
     * as referenced by [OpenID for VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html).
     */
    @Throws(IllegalArgumentException::class, CancellationException::class)
    private suspend fun validateVpToken(
        authnRequest: AuthenticationRequestParameters,
        responseParameters: ResponseParametersFrom,
    ): KmmResult<VpTokenValidationResult> = catching {
        val expectedNonce = authnRequest.nonce
            ?: throw IllegalArgumentException("nonce not present in $authnRequest")
        val vpToken = responseParameters.parameters.vpToken
            ?: throw IllegalArgumentException("vp_token not present in ${responseParameters.parameters}")
        val clientIdRequired = responseParameters.clientIdRequired

        val originalResponseParameters = responseParameters.originalResponseParameters

        (originalResponseParameters as? ResponseParametersFrom.DcApi)?.let {
            authnRequest.verifyExpectedOrigin(it.origin)
        }

        authnRequest.presentationDefinition?.let {
            val presentationSubmission = responseParameters.parameters.presentationSubmission?.descriptorMap
                ?: throw IllegalArgumentException("Presentation Exchange need to present a presentation submission.")

            val presentation = presentationSubmission.associate { descriptor ->
                descriptor.id to verifyPresentationResult(
                    claimFormat = descriptor.format,
                    relatedPresentation = descriptor.relatedPresentation(vpToken),
                    expectedNonce = expectedNonce,
                    input = responseParameters,
                    clientId = authnRequest.clientId,
                    responseUrl = authnRequest.responseUrl ?: authnRequest.redirectUrlExtracted,
                    transactionData = authnRequest.transactionData,
                    clientIdRequired = clientIdRequired,
                    origin = (originalResponseParameters as? ResponseParametersFrom.DcApi)?.origin,
                )
            }

            VpTokenValidationResultPresentationExchange(
                inputDescriptorResponseValidations = presentation,
            )
        } ?: authnRequest.dcqlQuery?.let { query ->
            val presentation = vpToken.jsonObject.mapKeys {
                DCQLCredentialQueryIdentifier(it.key)
            }.mapValues { (credentialQueryId, relatedPresentation) ->
                val credentialQuery = query.credentialQuery(credentialQueryId)
                    ?: throw IllegalArgumentException("Unknown credential query identifier.")

                relatedPresentation.jsonArray.map {
                    verifyPresentationResult(
                        claimFormat = credentialQuery.format.toClaimFormat(),
                        relatedPresentation = it.jsonPrimitive,
                        expectedNonce = expectedNonce,
                        input = responseParameters,
                        clientId = authnRequest.clientId,
                        responseUrl = authnRequest.responseUrl
                            ?: authnRequest.redirectUrlExtracted,
                        transactionData = authnRequest.transactionData,
                        clientIdRequired = clientIdRequired,
                        origin = (originalResponseParameters as? ResponseParametersFrom.DcApi)?.origin,
                        requireCryptographicHolderBinding = query.credentialQuery(credentialQueryId)?.requireCryptographicHolderBinding,
                    )
                }
            }
            val submissionRequirementsValidationResult = catching {
                val queryResponse = presentation.mapValues {
                    it.value.map {
                        it.getOrThrow()
                    }
                }
                DCQLQueryAdapter(query).checkSubmissionRequirements(
                    DCQLQueryResponse(queryResponse)
                ).getOrThrow()
            }

            // TODO: Validation errors are (sometimes) put into a VerifiableDCQLPresentationValidationResults which means that the success page is shown
            // However, if we return a ValidationError, a BadRequest is sent, which is not shown to the user in the UI
            VpTokenValidationResultDCQL(
                credentialQueryResponseValidations = presentation,
                submissionRequirementsValidationResult = submissionRequirementsValidationResult,
            )
        } ?: throw IllegalArgumentException("Unsupported presentation mechanism")
    }

    private fun DCQLQuery.credentialQuery(id: DCQLCredentialQueryIdentifier) =
        credentials.associateBy { it.id }[id]

    private fun PresentationSubmissionDescriptor.relatedPresentation(vpToken: JsonElement) =
        JsonPath(cumulativeJsonPath).query(vpToken).first().value

    private fun CredentialFormatEnum.toClaimFormat(): ClaimFormat = when (this) {
        CredentialFormatEnum.JWT_VC -> ClaimFormat.JWT_VP
        CredentialFormatEnum.DC_SD_JWT -> ClaimFormat.SD_JWT
        CredentialFormatEnum.MSO_MDOC -> ClaimFormat.MSO_MDOC
        CredentialFormatEnum.NONE,
        CredentialFormatEnum.JWT_VC_JSON_LD,
        CredentialFormatEnum.JSON_LD,
            -> throw IllegalStateException("Unsupported credential format")
    }

    /**
     * Extract and verifies verifiable presentations, according to format defined in
     * [OpenID for VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html),
     * as referenced by [OpenID for VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html).
     */
    private suspend fun verifyPresentationResult(
        claimFormat: ClaimFormat,
        relatedPresentation: JsonElement,
        expectedNonce: String,
        input: ResponseParametersFrom,
        clientId: String?,
        responseUrl: String?,
        transactionData: List<TransactionDataBase64Url>?,
        clientIdRequired: Boolean,
        origin: String?,
        requireCryptographicHolderBinding: Boolean? = null,
    ): KmmResult<Verifier.VerifyPresentationResult> = catching {
        when (claimFormat) {
            ClaimFormat.SD_JWT -> {
                val sdJwt = SdJwtSigned.parseCatching(relatedPresentation.extractContent()).getOrElse {
                    throw IllegalArgumentException("relatedPresentation")
                }
                nonceAwareVerifier.verifyPresentationSdJwt(
                    input = sdJwt,
                    challenge = expectedNonce,
                    transactionData = transactionData,
                    requireCryptographicHolderBinding = requireCryptographicHolderBinding != false,
                    audience = origin?.let { "origin:$it" },
                )
            }

            ClaimFormat.JWT_VP -> if (requireCryptographicHolderBinding != false) {
                nonceAwareVerifier.verifyPresentationVcJwt(
                    input = JwsCompactTyped<VerifiablePresentationJws>(
                        relatedPresentation.extractContent()
                    ),
                    challenge = expectedNonce
                )
            } else {
                nonceAwareVerifier.verifyUnsignedVcJws(
                    input = relatedPresentation.extractContent()
                ).map {
                    Verifier.VerifyPresentationResult.SuccessUnsigned(it.vc)
                }
            }

            ClaimFormat.MSO_MDOC -> nonceAwareVerifier.verifyPresentationIsoMdoc(
                input = relatedPresentation.extractContent().decodeToByteArray(Base64UrlStrict)
                    .let { coseCompliantSerializer.decodeFromByteArray<DeviceResponse>(it) },
                verifyDocument = verifyDocument(
                    sessionTranscript = createSessionTranscript(
                        input = input,
                        clientId = clientId,
                        expectedNonce = expectedNonce,
                        hasBeenEncrypted = input.hasBeenEncrypted,
                        responseUrl = responseUrl,
                        clientIdRequired = clientIdRequired,
                        origin = origin
                    )
                )
            )

            else -> throw IllegalArgumentException("descriptor.format: $claimFormat")
        }.getOrThrow()
    }

    private fun createSessionTranscript(
        input: ResponseParametersFrom,
        clientId: String?,
        expectedNonce: String,
        hasBeenEncrypted: Boolean,
        responseUrl: String?,
        clientIdRequired: Boolean,
        origin: String?,
    ): SessionTranscript {
        require((!clientIdRequired || clientId != null)) { "Missing required parameter: clientId" }
        require(responseUrl != null) { "Missing required parameter: responseUrl" }
        require(input.originalResponseParameters is ResponseParametersFrom.DcApi) {
            "Unsupported response mechanism: ${input.originalResponseParameters}"
        }
        require(origin != null) { "Missing required parameter: origin" }
        val serializedOrigin = requireNotNull(origin.serializeOrigin()) {
            "Invalid parameter: origin"
        }
        return createDcApiSessionTranscript(
            OpenID4VPDCAPIHandoverInfo(
                // Device signatures are bound to the HTML-serialized origin used by OpenID4VP/DCAPI.
                // Hashing the raw URL would make `https://example.com/` differ from `https://example.com`.
                origin = serializedOrigin,
                nonce = expectedNonce,
                jwkThumbprint = if (hasBeenEncrypted) {
                    decryptionKeyMaterial.jsonWebKey.sessionTranscriptThumbprint()
                } else null,
            )
        )
    }

    /**
     * Performs calculation of the [SessionTranscript] for DC API according to OID4VP
     */
    override fun createDcApiSessionTranscript(
        toBeHashed: SessionTranscriptContentHashable,
    ): SessionTranscript = SessionTranscript.forDcApi(
        DCAPIHandover(
            type = DCAPIHandover.TYPE_OPENID4VP,
            hash = coseCompliantSerializer.encodeToByteArray<OpenID4VPDCAPIHandoverInfo>(
                toBeHashed as? OpenID4VPDCAPIHandoverInfo
                    ?: throw IllegalArgumentException("Unsupported DCAPIHandoverInfo")
            ).sha256(),
        )
    )

    fun createDcApiSessionTranscriptAnnexC(
        toBeHashed: SessionTranscriptContentHashable,
    ): SessionTranscript = SessionTranscript.forDcApi(
        DCAPIHandover(
            type = TYPE_DCAPI,
            hash = coseCompliantSerializer.encodeToByteArray(
                toBeHashed as? DCAPIInfo ?: throw IllegalStateException("Expected DCAPIInfo")
            ).sha256(),
        )
    )

    // To be reconsidered when supporting [DCQLCredentialQueryInstance.multiple]
    private fun JsonElement.extractContent(): String = when (this) {
        is JsonArray -> first().extractContent()
        is JsonObject -> toString()
        is JsonPrimitive -> content
        JsonNull -> throw IllegalArgumentException("Can't extract string from JsonNull")
    }

    // should always be ecdh-es for encryption
    private fun JsonWebKey.withAlgorithm(): JsonWebKey = this.copy(algorithm = JweAlgorithm.ECDH_ES)
}

private val PresentationSubmissionDescriptor.cumulativeJsonPath: String
    get() {
        var cummulativeJsonPath = this.path
        var descriptorIterator = this.nestedPath
        while (descriptorIterator != null) {
            cummulativeJsonPath += descriptorIterator.path.substring(1)
            descriptorIterator = descriptorIterator.nestedPath
        }
        return cummulativeJsonPath
    }
