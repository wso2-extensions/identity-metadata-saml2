/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.idp.metadata.saml2.bean;

import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.idp.metadata.saml2.util.BuilderUtil;

/**
 * If metadata is not found, SAMLMetadataErrorResponse is returned.
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

    /**
     * Class which is responsible for building a SAML metadata error response.
     */
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
