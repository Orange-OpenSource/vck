import at.asitplus.wallet.lib.agent.ClaimToBeIssued;
import at.asitplus.wallet.lib.agent.InMemoryIssuerCredentialStore;
import at.asitplus.wallet.lib.agent.StatusListAgent;
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo;
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus;
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier;
import io.ktor.http.Url;

import java.util.List;

public class TestJavaApi {

    public void createsStatusListInfoFromJavaApi() {
        Url uri = UniformResourceIdentifier.fromString("https://example.com");

        StatusListInfo fromUri = StatusListInfo.fromUri(uri, 0, null);
        StatusListInfo fromString = new StatusListInfo("https://example.com", 0);

        assertStatusListInfo(fromUri);
        assertStatusListInfo(fromString);

        InMemoryIssuerCredentialStore store = new InMemoryIssuerCredentialStore();
        if (store.setStatusLong(0, 0, TokenStatus.INVALID)) {
            throw new AssertionError("empty store must not update a status");
        }

        StatusListAgent issuer = new StatusListAgent();
        if (issuer.revokeCredentialByIndexLong(0, 0)) {
            throw new AssertionError("empty issuer must not revoke a credential");
        }
    }

    public void createsNestedClaimFromJavaApi() {
        ClaimToBeIssued claim = ClaimToBeIssued.fromPath(List.of("address", "region"), "Vienna");
        if (!claim.getName().equals("address")) {
            throw new AssertionError("outer claim name missing");
        }
        if (!(claim.getValue() instanceof List<?> nested)
                || nested.size() != 1
                || !(nested.get(0) instanceof ClaimToBeIssued region)
                || !region.getName().equals("region")
                || !region.getValue().equals("Vienna")) {
            throw new AssertionError("nested claim missing");
        }
    }

    private static void assertStatusListInfo(StatusListInfo info) {
        if (info == null) {
            throw new AssertionError("StatusListInfo must not be null");
        }
        if (info.getCertificate() != null) {
            throw new AssertionError("certificate must default to null");
        }
        if (!info.toString().contains("https://example.com")) {
            throw new AssertionError("uri missing from StatusListInfo");
        }
    }

}
