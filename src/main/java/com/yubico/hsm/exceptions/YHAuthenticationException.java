/*
 * Copyright 2019 Yubico AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.yubico.hsm.exceptions;

import com.yubico.hsm.yhconcepts.YHError;

public class YHAuthenticationException extends YHException {

    public YHAuthenticationException(final String message) {
        super(message);
    }

    public YHAuthenticationException(final String message, final Throwable cause) {
        super(message, cause);
    }

    public YHAuthenticationException(final YHError errorCode) {
        super(errorCode, "Authentication failed. Error code: " + errorCode.toString());
    }

    public YHAuthenticationException(final YHError errorCode, final Throwable cause) {
        super(errorCode, "Authentication failed. Error code: " + errorCode.toString(), cause);
    }
}
