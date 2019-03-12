/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
 * Copyright 2015 PetalMD
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.petalmd.armor.authentication;

public class AuthException extends Exception {

    public enum ExceptionType {
        NOT_FOUND,
        ERROR
    }

    public ExceptionType type;

    public AuthException(ExceptionType type) {
            this.type = type;
    }

    public AuthException(final String message) {
        super(message);
        this.type = ExceptionType.ERROR;
    }

    public AuthException(final Throwable cause) {
        super(cause);
        this.type = ExceptionType.ERROR;
    }

    public AuthException(final String message, final Throwable cause) {
        super(message, cause);
        this.type = ExceptionType.ERROR;
    }

    public AuthException(final String message, final ExceptionType type) {
        super(message);
        this.type = type;
    }

    public AuthException(final Throwable cause, final ExceptionType type) {
        super(cause);
        this.type = type;
    }

    public AuthException(final String message, final Throwable cause, final ExceptionType type) {
        super(message, cause);
        this.type = type;
    }

}
