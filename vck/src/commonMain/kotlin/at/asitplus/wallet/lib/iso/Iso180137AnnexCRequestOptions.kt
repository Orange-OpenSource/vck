package at.asitplus.wallet.lib.iso

import at.asitplus.iso.DeviceRequest
import at.asitplus.wallet.lib.RequestOptions

data class Iso180137AnnexCRequestOptions(
    /**
     * Device request can be built using [CredentialPresentationRequestBuilder]
     */
    val deviceRequest: DeviceRequest,
    /** Transaction ID. */
    override val state: String,
) : RequestOptions