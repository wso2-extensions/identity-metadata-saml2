package org.wso2.carbon.identity.idp.metadata.saml2.bean;

import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.idp.metadata.saml2.util.BuilderUtil;

/**
 * If metadata is not found, SAMLMetadataErrorResponse is returned
 */
public class SAMLMetadataErrorResponse extends IdentityResponse {

    private String message;

    protected SAMLMetadataErrorResponse(IdentityResponse.IdentityResponseBuilder builder) {
        super(builder);

        message = ((SAMLMetadataErrorResponse.SAMLMetadataErrorResponseBuilder) builder).message;
    }


    public String getMessage() {
        return message;
    }

    public void setMessage(String metadata) {
        this.message = metadata;
    }

    public static class SAMLMetadataErrorResponseBuilder extends IdentityResponse.IdentityResponseBuilder {

        private String message;

        static {
            BuilderUtil.doBootstrap();
        }

        public SAMLMetadataErrorResponseBuilder(IdentityMessageContext context) {
            super(context);
        }

        public String getMessage() {
            return message;
        }

        public void setMessage(String metadata) {
            this.message = metadata;
        }

        @Override
        public IdentityResponse build() {
            return new SAMLMetadataErrorResponse(this);
        }
    }


}
