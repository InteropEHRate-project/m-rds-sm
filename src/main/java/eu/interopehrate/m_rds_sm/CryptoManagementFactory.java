package eu.interopehrate.m_rds_sm;


import eu.interopehrate.m_rds_sm.api.CryptoManagement;

/*
 *		Author: UBITECH
 *		Project: InteropEHRate - www.interopehrate.eu
 *
 *	Description: Interface of M-RDS-SM library.
 *	It allows the S-EHR application to securely share data.
 *
 */

public final class CryptoManagementFactory {
    private CryptoManagementFactory() {}

    /**
     * Factory method for creating an instance of EncryptedCommunication
     *
     * @return
     */
    public static CryptoManagement create(final String caUrl) {
        return new CryptoManagementImpl(caUrl);
    }
}
