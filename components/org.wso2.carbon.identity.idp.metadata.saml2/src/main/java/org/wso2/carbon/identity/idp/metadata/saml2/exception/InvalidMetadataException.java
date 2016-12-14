package org.wso2.carbon.identity.idp.metadata.saml2.exception;

/**
 * Created by pasindu on 11/10/16.
 */
public class InvalidMetadataException extends Exception {
    public InvalidMetadataException(String message) {
        super(message);
    }

    public InvalidMetadataException(String message, Throwable cause) {
        super(message, cause);
    }


}
