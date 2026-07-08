package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.dcapi.DCAPIHandover
import at.asitplus.dcapi.DCAPIHandover.Companion.TYPE_DCAPI
import at.asitplus.dcapi.DCAPIInfo
import at.asitplus.dcapi.DCAPIResponse
import at.asitplus.dcapi.DigitalCredentialInterface
import at.asitplus.dcapi.IsoMdocResponse
import at.asitplus.dcapi.OpenID4VPDCAPIHandoverInfo
import at.asitplus.dcapi.OpenId4VpResponse
import at.asitplus.dcapi.SessionTranscriptContentHashable
import at.asitplus.dcapi.request.IsoMdocRequest
import at.asitplus.dcapi.request.verifier.CredentialRequestOptions
import at.asitplus.dcapi.request.verifier.DigitalCredentialGetRequest
import at.asitplus.dcapi.request.verifier.DigitalCredentialGetRequest.*
import at.asitplus.dcapi.request.verifier.DigitalCredentialGetRequest.OpenId4Vp.SignedDataElement
import at.asitplus.dif.ClaimFormat
import at.asitplus.iso.DeviceResponse
import at.asitplus.iso.EncryptionInfo
import at.asitplus.iso.EncryptionParameters
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.serializeOrigin
import at.asitplus.iso.sha256
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.CredentialFormatEnum
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
import at.asitplus.openid.dcql.toIso180137AnnexCDeviceRequest
import at.asitplus.rfc6749OAuth2AuthorizationFramework.ResponseType
import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.cosef.toCoseAlgorithm
import at.asitplus.signum.indispensable.cosef.toCoseKey
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
import at.asitplus.wallet.lib.data.IsoDocumentParsed
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
import io.ktor.utils.io.core.*
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
    /** Used to store issued requests to verify the response to it */
    private val stateToIsoMdocRequestStore: MapStore<String, IsoMdocRequest> = DefaultMapStore(),
    /** Algorithms supported to decrypt responses from wallets, for [metadataWithEncryption]. */
    private val supportedJweEncryptionAlgorithms: Set<JweEncryption> = JweEncryption.entries.toSet(),
    /**
     * Workaround until signum is ready. Required for ISO 18013-7 Annex decryption.
     * Parameters: Serialized ephemeral key, cipher text, decryption key, encoded session transcript
     */
    private val decryptHpke: (suspend (ByteArray, ByteArray, CryptoPrivateKey.EC.WithPublicKey, ByteArray) -> ByteArray)? = null,
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
     *
     * Pass more than one [creationOptions] to offer the same request over several exchange protocols in one
     * browser call, e.g. [DcApiCreationOptions.OpenId4VpSigned] and [DcApiCreationOptions.Iso180137AnnexC].
     * Do not combine [DcApiCreationOptions.OpenId4VpSigned] and [DcApiCreationOptions.OpenId4VpUnsigned],
     * as the stored requests to validate the response would overwrite each other.
     */
    suspend fun createAuthnRequest(
        requestOptions: OpenId4VpRequestOptions,
        vararg creationOptions: DcApiCreationOptions,
    ): KmmResult<CredentialRequestOptions> = catching {
        require(requestOptions.isAnyDcApi) {
            "responseMode must be ${OpenIdConstants.ResponseMode.DcApi} or ${OpenIdConstants.ResponseMode.DcApiJwt}"
        }
        require(creationOptions.isNotEmpty()) {
            "at least one creation option is required"
        }
        CredentialRequestOptions.create(
            creationOptions.map { it.toGetRequest(requestOptions) }
        )
    }

    private suspend fun DcApiCreationOptions.toGetRequest(
        requestOptions: OpenId4VpRequestOptions,
    ): DigitalCredentialGetRequest = when (this) {
        is DcApiCreationOptions.OpenId4VpUnsigned -> OpenId4VpUnsigned(
            // client_id MUST be omitted in unsigned requests, per OpenID4VP 1.0 Appendix A.3.1
            createPlainAuthnRequest(requestOptions.requireEncryptionKeyConveyed().copy(populateClientId = false))
        )

        is DcApiCreationOptions.OpenId4VpSigned -> OpenId4VpSigned(
            SignedDataElement(
                createSignedRequestObject(requestOptions.requireEncryptionKeyConveyed()).getOrThrow().jws
            )
        )

        DcApiCreationOptions.Iso180137AnnexC -> {
            requireNotNull(decryptHpke) {
                "ISO 18013-7 Annex C requires decryptHpke to be set, the response could never be validated"
            }
            IsoMdoc(
                createIsoMdocRequest(requestOptions)
            )
        }
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

    private suspend fun createIsoMdocRequest(
        requestOptions: OpenId4VpRequestOptions,
    ): IsoMdocRequest {
        val deviceRequest = ((requestOptions.presentationRequest as? DCQLRequest)?.dcqlQuery
            ?: throw IllegalArgumentException("ISO 18013-7 Annex C requires a DCQL presentation request"))
            .toIso180137AnnexCDeviceRequest()

        val encryptionParameters = EncryptionParameters(
            nonceService.provideNonce().toByteArray(),
            decryptionKeyMaterial.publicKey.toCoseKey().getOrThrow()
        )
        return IsoMdocRequest(deviceRequest, EncryptionInfo(TYPE_DCAPI, encryptionParameters))
            .also { stateToIsoMdocRequestStore.put(requestOptions.state, it) }
    }

    private suspend fun OpenId4VpRequestOptions.toAuthnRequest(): AuthenticationRequestParameters =
        AuthenticationRequestParameters(
            responseType = responseType,
            clientId = if (populateClientId) clientIdScheme.clientId else null,
            redirectUrl = if (!isAnyDirectPost) clientIdScheme.redirectUri else null,
            responseUrl = responseUrl,
            // Using scope as an alias for a well-defined Presentation Exchange or DCQL is not supported
            scope = null,
            nonce = nonceAwareVerifier.provideNonce(),
            clientMetadata = clientMetadata(),
            idTokenType = null,
            responseMode = responseMode,
            state = null,
            // Presentation Exchange is not available for the DC API, only DCQL
            dcqlQuery = (presentationRequest as? DCQLRequest)?.dcqlQuery,
            transactionData = transactionData?.map { it.toBase64UrlJsonString() },
            expectedOrigins = expectedOrigins,
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

    /**
     * The DC API has no other channel to convey the verifier's encryption key: wallets can only encrypt responses
     * with a key from [at.asitplus.openid.AuthenticationRequestParameters.clientMetadata] in the request itself.
     */
    private fun OpenId4VpRequestOptions.requireEncryptionKeyConveyed(): OpenId4VpRequestOptions = also {
        if (responseMode.requiresEncryption) {
            requireNotNull(clientMetadata()?.jsonWebKeySet) {
                "Encrypted responses require client metadata with a JSON Web Key Set in the request, " +
                        "which is not populated for this client identifier scheme"
            }
        }
    }

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
    ): KmmResult<DcApiResponseResult> = catching {
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
    ): KmmResult<DcApiResponseResult> = catching {
        when (input) {
            is IsoMdocResponse -> validateIsoResponse(
                receivedData = input.data,
                externalId = externalId,
                expectedOrigin = "TODO"
            ).getOrThrow()

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

    @OptIn(SecretExposure::class)
    internal suspend fun validateIsoResponse(
        receivedData: DCAPIResponse,
        externalId: String,
        expectedOrigin: String
    ): KmmResult<Iso180137AnnexCWrapper> = catching {
        val isoMdocRequest = stateToIsoMdocRequestStore.get(externalId)!!
        val privateKey = decryptionKeyMaterial.exportPrivateKey().getOrThrow()
                as? CryptoPrivateKey.EC.WithPublicKey
            ?: throw IllegalStateException("Expected EC private key")

        val encryptedResponseData = receivedData.response.encryptedResponseData
        val serializedOrigin = expectedOrigin.serializeOrigin()
            ?: throw IllegalStateException("Expected origin invalid")

        val sessionTranscript = createDcApiSessionTranscriptAnnexC(
            DCAPIInfo(
                encryptionInfo = isoMdocRequest.encryptionInfo,
                serializedOrigin = serializedOrigin,
            )
        )
        val encodedSessionTranscript = coseCompliantSerializer.encodeToByteArray(sessionTranscript)
        val encodedDeviceResponse = requireNotNull(decryptHpke) { "decryptHpke required for ISO 18013-7 Annex C" }(
            encryptedResponseData.enc,
            encryptedResponseData.cipherText,
            privateKey,
            encodedSessionTranscript
        )
        val deviceResponse = coseCompliantSerializer.decodeFromByteArray<DeviceResponse>(encodedDeviceResponse)

        val documents = verifier.verifyPresentationIsoMdoc(
            input = deviceResponse,
            verifyDocument = verifyDocument(
                sessionTranscript = sessionTranscript
            )
        ).getOrThrow().documents

        // an authentic document of a type we never asked for must not be mistaken for the requested one
        val requestedDocTypes = isoMdocRequest.deviceRequest.docRequests
            .map { it.itemsRequest.value.docType }.toSet()
        documents.forEach { document ->
            require(document.document.docType in requestedDocTypes) {
                "Response contains docType '${document.document.docType}', but requested were $requestedDocTypes"
            }
        }

        Iso180137AnnexCWrapper(documents)
    }

    private fun AuthnResponseResult.isFullyValid(): Boolean =
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
        require(originalResponseParameters is ResponseParametersFrom.DcApi) {
            "Unsupported response parameters: $originalResponseParameters"
        }
        authnRequest.verifyExpectedOrigin(originalResponseParameters.origin)

        authnRequest.dcqlQuery?.let { query ->
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
                        origin = originalResponseParameters.origin,
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

sealed class DcApiResponseResult {

}

data class Iso180137AnnexCWrapper(val documents: Collection<IsoDocumentParsed>) : DcApiResponseResult()