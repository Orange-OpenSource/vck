package at.asitplus.wallet.eupidsdjwt

object EuPidSdJwtDataElements {
    /** Current last name(s) or surname(s) of the user to whom the person identification data relates. */
    const val FAMILY_NAME = "family_name"

    /** Current first name(s), including middle name(s) where applicable, of the user to whom the person identification data relates. */
    const val GIVEN_NAME = "given_name"

    /** Day, month, and year on which the user to whom the person identification data relates was born. */
    const val BIRTH_DATE = "birthdate"

    /** Last name(s) or surname(s) of the User to whom the person identification data relates at the time of birth. */
    const val FAMILY_NAME_BIRTH = "birth_family_name"

    /** First name(s), including middle name(s), of the User to whom the person identification data relates at the time of birth. */
    const val GIVEN_NAME_BIRTH = "birth_given_name"

    /** Place of birth prefix, see [PlaceOfBirth] */
    const val PREFIX_PLACE_OF_BIRTH = "place_of_birth"

    /** The country where the PID User was born, as an Alpha-2 country code as specified in ISO 3166-1. */
    const val PLACE_OF_BIRTH_COUNTRY = "$PREFIX_PLACE_OF_BIRTH.country"

    /** The state, province, district, or local area where the PID User was born. */
    const val PLACE_OF_BIRTH_REGION = "$PREFIX_PLACE_OF_BIRTH.region"

    /** The country as an alpha-2 country code as specified in ISO 3166-1, or the state, province, district, or
     *  local area or the municipality, city, town, or village where the user to whom the person identification
     *  data relates was born. */
    const val PLACE_OF_BIRTH_LOCALITY = "$PREFIX_PLACE_OF_BIRTH.locality"

    object PlaceOfBirth {
        /** The country where the PID User was born, as an Alpha-2 country code as specified in ISO 3166-1. */
        const val COUNTRY = "country"

        /** The state, province, district, or local area where the PID User was born. */
        const val REGION = "region"

        /** The country as an alpha-2 country code as specified in ISO 3166-1, or the state, province, district, or
         *  local area or the municipality, city, town, or village where the user to whom the person identification
         *  data relates was born. */
        const val LOCALITY = "locality"
    }

    /** Address prefix, see [Address] */
    const val PREFIX_ADDRESS = "address"

    /**
     * The full address of the place where the PID User currently resides and/or can be contacted
     * (street name, house number, city etc.).
     */
    const val ADDRESS_FORMATTED = "$PREFIX_ADDRESS.formatted"

    /** The country where the PID User currently resides, as an Alpha-2 country code as specified in ISO 3166-1. */
    const val ADDRESS_COUNTRY = "$PREFIX_ADDRESS.country"

    /** The state, province, district, or local area where the PID User currently resides. */
    const val ADDRESS_REGION = "$PREFIX_ADDRESS.region"

    /** The municipality, city, town, or village where the PID User currently resides. */
    const val ADDRESS_LOCALITY = "$PREFIX_ADDRESS.locality"

    /** Postal code of the place where the PID User currently resides. */
    const val ADDRESS_POSTAL_CODE = "$PREFIX_ADDRESS.postal_code"

    /** The name of the street where the PID User currently resides. */
    const val ADDRESS_STREET = "$PREFIX_ADDRESS.street_address"

    /** The house number where the PID User currently resides, including any affix or suffix. */
    const val ADDRESS_HOUSE_NUMBER = "$PREFIX_ADDRESS.house_number"

    object Address {
        /**
         * The full address of the place where the user to whom the person identification data relates currently
         * resides or can be contacted (street name, house number, city etc.).
         */
        const val FORMATTED = "formatted"

        /** The country where the user to whom the person identification data relates currently resides, as an
         * alpha-2 country code as specified in ISO 3166-1. */
        const val COUNTRY = "country"

        /** The state, province, district, or local area where the user to whom the person identification data
         * relates currently resides. */
        const val REGION = "region"

        /** The municipality, city, town, or village where the user to whom the person identification data relates
         *  currently resides. */
        const val LOCALITY = "locality"

        /** The postal code of the place where the user to whom the person identification data relates currently
         * resides. */
        const val POSTAL_CODE = "postal_code"

        /** The name of the street where the user to whom the person identification data relates currently resides. */
        const val STREET = "street_address"

        /** The house number where the user to whom the person identification data relates currently resides,
         *  including any affix or suffix. */
        const val HOUSE_NUMBER = "house_number"
    }

    /** See [IsoIec5218Gender]. */
    const val SEX = "sex"

    /** One or more alpha-2 country codes as specified in ISO 3166-1, representing the nationality of the user to
     *  whom the person identification data relates. */
    const val NATIONALITIES = "nationalities"

    /** Date (and if possible time) when the person identification data was issued and/or the administrative validity period of the person identification data began. */
    const val ISSUANCE_DATE = "date_of_issuance"

    /** Date (and if possible time) when the person identification data will expire. */
    const val EXPIRY_DATE = "date_of_expiry"

    /**
     * Name of the administrative authority that has issued this PID instance, or
     * the ISO 3166 Alpha-2 country code of the respective Member State if
     * there is no separate authority authorized to issue PIDs.
     */
    const val ISSUING_AUTHORITY = "issuing_authority"

    /** A number for the PID, assigned by the PID Provider. */
    const val DOCUMENT_NUMBER = "document_number"

    /** Alpha-2 country code, as defined in ISO 3166-1, of the PID Provider's country or territory. */
    const val ISSUING_COUNTRY = "issuing_country"

    /**
     * Country subdivision code of the jurisdiction that issued the PID, as
     * defined in ISO 3166-2:2020, Clause 8. The first part of the code SHALL
     * be the same as the value for [ISSUING_COUNTRY].
     */
    const val ISSUING_JURISDICTION = "issuing_jurisdiction"

    /**
     * A value assigned to the natural person that is unique among all personal administrative numbers issued by the
     * provider of person identification data. Where Member States opt to include this attribute, they shall
     * describe in their electronic identification schemes under which the person identification data is issued,
     * the policy that they apply to the values of this attribute, including, where applicable, specific conditions
     * for the processing of this value.
     */
    const val PERSONAL_ADMINISTRATIVE_NUMBER = "personal_administrative_number"

    /** Facial image of the wallet user compliant with ISO 19794-5 or ISO 39794 specifications. */
    const val PORTRAIT = "picture"

    /** Electronic mail address of the user to whom the person identification data relates, in conformance with [RFC 5322]. */
    const val EMAIL = "email"

    /** Mobile telephone number of the User to whom the person identification data relates, starting with the '+'
     * symbol as the international code prefix and the country code, followed by numbers only. */
    const val PHONE_NUMBER = "phone_number"

    /** This attribute indicates at least the URL at which a machine-readable version of the trust anchor to be used for verifying the PID can be found or looked up */
    const val TRUST_ANCHOR = "trust_anchor"

}