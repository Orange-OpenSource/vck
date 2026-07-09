package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.dcapi.OpenId4VpResponse
import at.asitplus.dif.ClaimFormat
import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.FormatContainerJwt
import at.asitplus.dif.FormatContainerSdJwt
import at.asitplus.dif.PresentationSubmissionDescriptor
import at.asitplus.iso.DeviceResponse
import at.asitplus.iso.OpenId4VpHandover
import at.asitplus.iso.OpenId4VpHandoverInfo
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.sha256
import at.asitplus.jsonpath.JsonPath
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.IdToken
import at.asitplus.openid.IdTokenType
import at.asitplus.openid.JarRequestParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.RelyingPartyMetadata
import at.asitplus.openid.RequestObjectParameters
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
import at.asitplus.wallet.lib.DefaultNonceService
import at.asitplus.wallet.lib.MdocDeviceSignatureVerifier
import at.asitplus.wallet.lib.NonceService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.NonceChallengeVerifier
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.agent.Verifier.VerifyPresentationResult
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
import at.asitplus.wallet.lib.oidvci.encodeToParameters
import at.asitplus.wallet.lib.procedures.dcql.DCQLQueryAdapter
import at.asitplus.wallet.lib.utils.DefaultMapStore
import at.asitplus.wallet.lib.utils.MapStore
import io.github.aakira.napier.Napier
import io.ktor.http.*
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
import kotlin.time.Clock
import kotlin.time.DurationUnit
import kotlin.time.toDuration

/**
 * Combines Verifiable Presentations with OAuth 2.0.
 * Implements [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) (1.0, 2025-07-09)
 * as well as [SIOP V2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html) (D13, 2023-11-28).
 *
 * This class creates the Authentication Request (see [AuthenticationRequestParameters]),
 * clients need to send it to the holder (see [OpenId4VpHolder]) which will create the Authentication Response,
 * which will be verified here in [validateAuthnResponse].
 */
class OpenId4VpVerifier @JvmOverloads constructor(
    /** Scheme to use for our client identifier. */
    private val clientIdScheme: ClientIdScheme,
    /** Key material to sign the authentication request with [signAuthnRequest]. */
    private val keyMaterial: KeyMaterial = EphemeralKeyWithoutCert(),
    /** Verifies the holder's response against our identifier from [clientIdScheme]. */
    val verifier: Verifier = VerifierAgent(identifier = clientIdScheme.clientId),
    /** Advertised in [metadata] so that holders can encrypt responses. */
    private val decryptionKeyMaterial: KeyMaterial = EphemeralKeyWithoutCert(),
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
    private val verifyCoseSignature: VerifyCoseSignatureWithKeyFun<ByteArray> = VerifyCoseSignatureWithKey(),
    /** Leeway for time validity checks. */
    timeLeewaySeconds: Long = 300L,
    /** Clock for time validity checks. */
    private val clock: Clock = Clock.System,
    /** Creates and validates OpenID4VP request nonces. */
    private val nonceService: NonceService = DefaultNonceService(),
    /** Used to store issued authn requests to verify the authn response to it */
    private val stateToAuthnRequestStore: MapStore<String, AuthenticationRequestParameters> = DefaultMapStore(),
    /** Algorithms supported to decrypt responses from wallets, for [metadataWithEncryption]. */
    private val supportedJweEncryptionAlgorithms: Set<JweEncryption> = JweEncryption.entries.toSet(),
) {

    private val mdocDeviceSignatureVerifier = MdocDeviceSignatureVerifier(verifyCoseSignature = verifyCoseSignature)

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
    private val timeLeeway = timeLeewaySeconds.toDuration(DurationUnit.SECONDS)
    private val containerJwt = FormatContainerJwt(algorithmStrings = supportedJwsAlgorithms)
    private val containerSdJwt = FormatContainerSdJwt(
        sdJwtAlgorithmStrings = supportedJwsAlgorithms.toSet(),
        kbJwtAlgorithmStrings = supportedJwsAlgorithms.toSet()
    )

    @Deprecated("Moved to upper level", ReplaceWith("CreationOptions", "at.asitplus.wallet.lib.openid.CreationOptions"))
    typealias CreationOptions = at.asitplus.wallet.lib.openid.CreationOptions

    @Deprecated("Moved to upper level", ReplaceWith("CreatedRequest", "at.asitplus.wallet.lib.openid.CreatedRequest"))
    typealias CreatedRequest = at.asitplus.wallet.lib.openid.CreatedRequest

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
     * Creates a new authentication request conforming to OpenID4VP.
     */
    suspend fun createAuthnRequest(
        requestOptions: OpenId4VpRequestOptions,
        creationOptions: at.asitplus.wallet.lib.openid.CreationOptions,
    ): KmmResult<at.asitplus.wallet.lib.openid.CreatedRequest> = catching {
        when (creationOptions) {
            is CreationOptions.Query -> {
                require(clientIdScheme !is ClientIdScheme.CertificateSanDns) // per OpenID4VP d23 5.10.4
                URLBuilder(creationOptions.walletUrl).apply {
                    createPlainAuthnRequest(requestOptions).encodeToParameters()
                        .forEach { parameters.append(it.key, it.value) }
                }.buildString().toCreatedRequest()
            }

            is CreationOptions.RequestByReference -> {
                require(clientIdScheme !is ClientIdScheme.CertificateSanDns) // per OpenID4VP d23 5.10.4
                URLBuilder(creationOptions.walletUrl).apply {
                    JarRequestParameters(
                        clientId = clientIdScheme.clientId,
                        requestUri = creationOptions.requestUrl,
                        requestUriMethod = creationOptions.requestUrlMethod,
                    ).encodeToParameters()
                        .forEach { parameters.append(it.key, it.value) }
                }.buildString().toCreatedRequest {
                    catching {
                        joseCompliantSerializer.encodeToString(createPlainAuthnRequest(requestOptions, it))
                    }
                }
            }

            is CreationOptions.SignedRequestByValue -> {
                require(clientIdScheme !is ClientIdScheme.RedirectUri) // per OpenID4VP d23 5.10.4
                URLBuilder(creationOptions.walletUrl).apply {
                    JarRequestParameters(
                        clientId = clientIdScheme.clientId,
                        request = createSignedRequestObject(requestOptions).getOrThrow().toString(),
                    ).encodeToParameters()
                        .forEach { parameters.append(it.key, it.value) }
                }.buildString().toCreatedRequest()
            }

            is CreationOptions.SignedRequestByReference -> {
                require(clientIdScheme !is ClientIdScheme.RedirectUri) // per OpenID4VP d23 5.10.4
                URLBuilder(creationOptions.walletUrl).apply {
                    JarRequestParameters(
                        clientId = clientIdScheme.clientId,
                        requestUri = creationOptions.requestUrl,
                        requestUriMethod = creationOptions.requestUrlMethod,
                    ).encodeToParameters()
                        .forEach { parameters.append(it.key, it.value) }
                }.buildString()
                    .toCreatedRequest {
                        catching {
                            createSignedRequestObject(requestOptions, it).getOrThrow().toString()
                        }
                    }
            }
        }
    }

    private fun String.toCreatedRequest() = at.asitplus.wallet.lib.openid.CreatedRequest(this)
    private fun String.toCreatedRequest(
        loadRequestObject: suspend (RequestObjectParameters?) -> KmmResult<String>,
    ) = at.asitplus.wallet.lib.openid.CreatedRequest(this, loadRequestObject)

    @Deprecated("Use createAuthnRequest instead with CreationOptions.SignedRequestByReference")
    suspend fun createAuthnRequestAsSignedRequestObject(
        requestOptions: OpenId4VpRequestOptions,
        requestObjectParameters: RequestObjectParameters? = null,
    ): KmmResult<JwsCompactTyped<AuthenticationRequestParameters>> =
        createSignedRequestObject(requestOptions, requestObjectParameters)

    internal suspend fun createSignedRequestObject(
        requestOptions: OpenId4VpRequestOptions,
        requestObjectParameters: RequestObjectParameters? = null,
    ): KmmResult<JwsCompactTyped<AuthenticationRequestParameters>> = catching {
        val requestObject = createPlainAuthnRequest(requestOptions, requestObjectParameters)
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

    @Deprecated("Use createAuthnRequest instead with CreationOptions.SignedRequestByValue")
    suspend fun createAuthnRequest(
        requestOptions: OpenId4VpRequestOptions,
        requestObjectParameters: RequestObjectParameters? = null,
    ) = createPlainAuthnRequest(requestOptions, requestObjectParameters)

    internal suspend fun createPlainAuthnRequest(
        requestOptions: OpenId4VpRequestOptions,
        requestObjectParameters: RequestObjectParameters? = null,
    ) = requestOptions.toAuthnRequest(requestObjectParameters)
        .also { storeAuthnRequest(it) }

    private suspend fun OpenId4VpRequestOptions.toAuthnRequest(
        requestObjectParameters: RequestObjectParameters?,
    ): AuthenticationRequestParameters = AuthenticationRequestParameters(
        responseType = responseType,
        clientId = if (populateClientId) clientIdScheme.clientId else null,
        redirectUrl = if (!isAnyDirectPost) clientIdScheme.redirectUri else null,
        responseUrl = responseUrl,
        // Using scope as an alias for a well-defined Presentation Exchange or DCQL is not supported
        scope = if (isSiop) buildScope() else null,
        nonce = nonceAwareVerifier.provideNonce(),
        walletNonce = requestObjectParameters?.walletNonce,
        clientMetadata = clientMetadata(),
        idTokenType = if (isSiop) IdTokenType.SUBJECT_SIGNED.text else null,
        responseMode = responseMode,
        state = state,
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

    @Deprecated("Should not be necessary at all, simply call [createAuthnRequest]")
    suspend fun submitAuthnRequest(
        authenticationRequestParameters: AuthenticationRequestParameters,
        externalId: String? = null,
    ) = storeAuthnRequest(authenticationRequestParameters)

    internal suspend fun storeAuthnRequest(
        authenticationRequestParameters: AuthenticationRequestParameters,
    ) = stateToAuthnRequestStore.put(
        key = authenticationRequestParameters.state
            ?: throw IllegalArgumentException("No state has been provided"),
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
     * Validates an Authentication Response from the Wallet, where [input] is either:
     * - a URL, containing parameters in the fragment, e.g. `https://example.com#id_token=...`
     * - a URL, containing parameters in the query, e.g. `https://example.com?id_token=...`
     * - parameters encoded as a POST body, e.g. `id_token=...&vp_token=...`
     */
    suspend fun validateAuthnResponse(
        input: String,
    ): KmmResult<AuthnResponseResult> = catching {
        val response = responseParser.parseAuthnResponse(input)
        validateAuthnResponse(response).getOrThrow()
    }

    @Suppress("DEPRECATION")
    @Deprecated("OpenID4VP doesn't support externalId, the state is always available")
    suspend fun validateAuthnResponse(
        input: String,
        externalId: String? = null,
    ): KmmResult<AuthnResponseResult> = catching {
        val response = responseParser.parseAuthnResponse(input)
        validateAuthnResponse(response, externalId).getOrThrow()
    }

    @Suppress("DEPRECATION")
    @Deprecated("Use DCAPI Verifier for that")
    suspend fun validateAuthnResponse(
        input: OpenId4VpResponse,
        externalId: String,
    ): KmmResult<AuthnResponseResult> = catching {
        val response = responseParser.parseAuthnResponse(input)
        validateAuthnResponse(response, externalId).getOrThrow()
    }

    /**
     * Validates an Authentication Response from the Wallet,
     * in case it has been parsed into [ResponseParametersFrom] with [ResponseParser].
     */
    suspend fun validateAuthnResponse(
        input: ResponseParametersFrom,
    ) = catching {
        Napier.d("validateAuthnResponse: $input")
        val authnRequest = loadAuthnRequest(input)

        val responseType = authnRequest.responseType?.let { ResponseType(it) }
        require(responseType != null) {
            "No response type was specified in the original authentication request."
        }

        val expectedNonce = authnRequest.nonce
            ?: throw IllegalArgumentException("nonce not present in $authnRequest")
        val idTokenValidationResult = if (OpenIdConstants.ID_TOKEN in responseType) {
            extractValidatedIdToken(input, expectedNonce)
        } else {
            null
        }
        val vpTokenValidationResult = if (OpenIdConstants.VP_TOKEN in responseType) {
            validateVpToken(authnRequest, input)
        } else {
            null
        }

        require(listOfNotNull(idTokenValidationResult, vpTokenValidationResult).isNotEmpty()) {
            "Unsupported response type: $responseType"
        }

        AuthnResponseResult(
            idTokenValidationResult = idTokenValidationResult,
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

    @Deprecated("OpenID4VP doesn't support externalId, the state is always available")
    suspend fun validateAuthnResponse(
        input: ResponseParametersFrom,
        externalId: String? = null,
    ): KmmResult<AuthnResponseResult> = validateAuthnResponse(input)

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
    ): AuthenticationRequestParameters {
        val storedId = input.parameters.state
            ?: throw IllegalArgumentException("No state in input parameters")
        val authnRequest = stateToAuthnRequestStore.get(storedId)
            ?: throw IllegalArgumentException("No authn request found for $storedId")
        if (authnRequest.responseMode?.requiresEncryption == true)
            require(input.hasBeenEncrypted) {
                "response_mode requires encryption, but no encrypted response was given"
            }
        return authnRequest
    }

    @Throws(IllegalArgumentException::class, CancellationException::class)
    private suspend fun extractValidatedIdToken(
        input: ResponseParametersFrom,
        expectedNonce: String,
    ): KmmResult<IdToken> = catching {
        val idTokenJws = input.parameters.idToken
            ?: throw IllegalArgumentException("idToken")
        val jwsSigned = catching { JwsCompactTyped<IdToken>(idTokenJws) }
            .getOrElse { throw IllegalArgumentException("idToken", it) }
        verifyJwsObject(jwsSigned.jws).getOrElse {
            throw IllegalArgumentException("idToken.", it)
                .also { Napier.w { "JWS of idToken not verified: $idTokenJws" } }
        }
        val idToken = jwsSigned.payload
        require(idToken.issuer == idToken.subject) {
            "Wrong issuer: ${idToken.issuer}, expected: ${idToken.subject}"
        }
        require(idToken.audience == clientIdScheme.clientId) {
            "audience not valid: ${idToken.audience}"
        }
        require(idToken.expiration >= (clock.now() - timeLeeway)) {
            "expirationDate before now: ${idToken.expiration}"
        }
        require(idToken.issuedAt <= (clock.now() + timeLeeway)) {
            "issuedAt after now: ${idToken.issuedAt}"
        }
        require(idToken.nonce == expectedNonce && nonceAwareVerifier.verifyNonce(expectedNonce)) {
            "nonce not valid: ${idToken.nonce}, expected $expectedNonce"
        }
        require(idToken.subjectJwk != null) {
            "sub_jwk is null"
        }
        require(idToken.subject == idToken.subjectJwk!!.jwkThumbprint) {
            "subject does not equal thumbprint of sub_jwk: ${idToken.subject}"
        }
        idToken
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
        require(originalResponseParameters !is ResponseParametersFrom.DcApi) {
            "DCAPI verification is not supported, use DcApiVerifier"
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
                    origin = null,
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
                        origin = null,
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
    ): KmmResult<VerifyPresentationResult> = catching {
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
                    VerifyPresentationResult.SuccessUnsigned(it.vc)
                }
            }

            ClaimFormat.MSO_MDOC -> nonceAwareVerifier.verifyPresentationIsoMdoc(
                input = relatedPresentation.extractContent().decodeToByteArray(Base64UrlStrict)
                    .let { coseCompliantSerializer.decodeFromByteArray<DeviceResponse>(it) },
                verifyDocument = mdocDeviceSignatureVerifier.verifyDocument(
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
        require(input.originalResponseParameters !is ResponseParametersFrom.DcApi) {
            "DCAPI verification is not supported, use DcApiVerifier"
        }

        return SessionTranscript.forOpenId(
            OpenId4VpHandover(
                type = OpenId4VpHandover.TYPE_OPENID4VP,
                hash = coseCompliantSerializer.encodeToByteArray<OpenId4VpHandoverInfo>(
                    OpenId4VpHandoverInfo(
                        clientId = clientId,
                        nonce = expectedNonce,
                        jwkThumbprint = if (hasBeenEncrypted) {
                            decryptionKeyMaterial.jsonWebKey.sessionTranscriptThumbprint()
                        } else null,
                        responseUrl = responseUrl,
                    )
                ).sha256(),
            )
        )
    }

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


