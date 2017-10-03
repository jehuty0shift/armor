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

package com.petalmd.armor.audit;

import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.transport.TransportRequest;

public interface AuditListener {
    default void onFailedLogin(String username, RestRequest request, ThreadContext threadContext){}

    default void onMissingPrivileges(String username, RestRequest request, ThreadContext threadContext){}

    default void onFailedLogin(String username, TransportRequest request, ThreadContext threadContext){}

    default void onMissingPrivileges(String username, TransportRequest request, ThreadContext threadContext){}
}
