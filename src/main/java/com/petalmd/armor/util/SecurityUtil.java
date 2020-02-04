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

package com.petalmd.armor.util;

import com.google.common.io.BaseEncoding;
import io.netty.handler.codec.http.cookie.Cookie;
import io.netty.handler.codec.http.cookie.ServerCookieDecoder;
import org.apache.commons.pool.impl.GenericObjectPool;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.ldap.client.api.*;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestRequest;

import javax.crypto.*;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManagerFactory;
import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SecurityUtil {

    private static final Logger log = LogManager.getLogger(SecurityUtil.class);
    private static final String[] PREFERRED_SSL_CIPHERS = { "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",  "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
             "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA" };
    private static final String[] PREFERRED_SSL_PROTOCOLS = {"TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1"};

    private static String[] ENABLED_SSL_PROTOCOLS = null;
    private static String[] ENABLED_SSL_CIPHERS = null;

    private static LdapConnectionPool ldapConnectionPool;

    private SecurityUtil() {

    }

    static {
        try {
            final int aesMaxKeyLength = Cipher.getMaxAllowedKeyLength("AES");

            if (aesMaxKeyLength < 256) {
                log.warn("AES 256 not supported, max key length for AES is " + aesMaxKeyLength
                        + ". To enable AES 256 install 'Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files'");
            }
        } catch (final NoSuchAlgorithmException e) {
            log.error("AES encryption not supported. " + e);

        }

        try {

            final SSLContext serverContext = SSLContext.getInstance("TLS");
            serverContext.init(null, null, null);
            final SSLEngine engine = serverContext.createSSLEngine();
            final List<String> supportedCipherSuites = new ArrayList<String>(Arrays.asList(engine.getSupportedCipherSuites()));
            final List<String> supportedProtocols = new ArrayList<String>(Arrays.asList(engine.getSupportedProtocols()));

            final List<String> preferredCipherSuites = Arrays.asList(PREFERRED_SSL_CIPHERS);
            final List<String> preferredProtocols = Arrays.asList(PREFERRED_SSL_PROTOCOLS);

            supportedCipherSuites.retainAll(preferredCipherSuites);
            supportedProtocols.retainAll(preferredProtocols);

            if (supportedCipherSuites.isEmpty()) {
                log.error("No usable SSL/TLS cipher suites found");
            } else {
                ENABLED_SSL_CIPHERS = supportedCipherSuites.toArray(new String[0]);
            }

            if (supportedProtocols.isEmpty()) {
                log.error("No usable SSL/TLS protocols found");
            } else {
                ENABLED_SSL_PROTOCOLS = supportedProtocols.toArray(new String[0]);
            }

            log.debug("Usable SSL/TLS protocols: {}", supportedProtocols);
            log.debug("Usable SSL/TLS cipher suites: {}", supportedCipherSuites);

        } catch (final NoSuchAlgorithmException | KeyManagementException e) {
            log.error("Error while evaluating supported crypto", e);
        }
    }

    public static Path getAbsoluteFilePathFromClassPath(final String fileNameFromClasspath) {

        Path jaasConfigFile = null;
        final URL jaasConfigURL = SecurityUtil.class.getClassLoader().getResource(fileNameFromClasspath);
        if (jaasConfigURL != null) {
            try {
                jaasConfigFile = Path.of(jaasConfigURL.toURI());
            } catch (final URISyntaxException e) {
                return null;
            }

            if (Files.exists(jaasConfigFile) && Files.isReadable(jaasConfigFile)) {
                return jaasConfigFile;
            } else {
                log.error("Cannot read from {}, maybe the file does not exists? ", jaasConfigFile.toString());
            }

        } else {
            log.error("Failed to load " + fileNameFromClasspath);
        }

        return null;

    }

    public static boolean setSystemPropertyToAbsoluteFilePathFromClassPath(final String property, final String fileNameFromClasspath) {
        if (System.getProperty(property) == null) {
            File jaasConfigFile = null;
            final URL jaasConfigURL = SecurityUtil.class.getClassLoader().getResource(fileNameFromClasspath);
            if (jaasConfigURL != null) {
                try {
                    jaasConfigFile = new File(URLDecoder.decode(jaasConfigURL.getFile(), "UTF-8"));
                } catch (final UnsupportedEncodingException e) {
                    return false;
                }

                if (jaasConfigFile.exists() && jaasConfigFile.canRead()) {
                    System.setProperty(property, jaasConfigFile.getAbsolutePath());

                    log.debug("Load " + fileNameFromClasspath + " from {} ", jaasConfigFile.getAbsolutePath());
                    return true;
                } else {
                    log.error("Cannot read from {}, maybe the file does not exists? ", jaasConfigFile.getAbsolutePath());
                }

            } else {
                log.error("Failed to load " + fileNameFromClasspath);
            }
        } else {
            log.warn("Property " + property + " already set to " + System.getProperty(property));
        }

        return false;
    }

    public static boolean setSystemPropertyToAbsoluteFile(final String property, final String fileName) {
        if (System.getProperty(property) == null) {

            if (fileName == null) {
                log.error("Cannot set property " + property + " because filename is null");

                return false;
            }

            final File jaasConfigFile = new File(fileName).getAbsoluteFile();

            if (jaasConfigFile.exists() && jaasConfigFile.canRead()) {
                System.setProperty(property, jaasConfigFile.getAbsolutePath());

                log.debug("Load " + fileName + " from {} ", jaasConfigFile.getAbsolutePath());
                return true;
            } else {
                log.error("Cannot read from {}, maybe the file does not exists? ", jaasConfigFile.getAbsolutePath());
            }

        } else {
            log.warn("Property " + property + " already set to " + System.getProperty(property));
        }

        return false;
    }


    public static boolean isWildcardMatch(final String toCheckForMatch, final String pattern, final boolean alsoViceVersa) {

        String escapedPattern = pattern.replace(".", "\\.").replace("*", ".*");
        Pattern regexPattern = Pattern.compile(escapedPattern);
        Matcher matcher = regexPattern.matcher(toCheckForMatch);
        final boolean normalMatch = matcher.matches();

        if (alsoViceVersa) {

            if (normalMatch) {
                return normalMatch;
            }

            escapedPattern = toCheckForMatch.replace(".", "\\.").replace("*", ".*");
            regexPattern = Pattern.compile(escapedPattern);
            matcher = regexPattern.matcher(pattern);
            return matcher.matches();

        } else {
            return normalMatch;
        }
    }

    public static LdapConnection getLdapConnection(final Settings settings) throws KeyStoreException, NoSuchAlgorithmException,
            CertificateException, IOException, LdapException {

        if (ldapConnectionPool != null) {
            LdapConnection ldapConnection = ldapConnectionPool.getConnection();
            if (ldapConnection != null) {
                return ldapConnection;
            }
        }

        final boolean useSSL = settings.getAsBoolean(ConfigConstants.ARMOR_AUTHENTICATION_LDAP_LDAPS_SSL_ENABLED, false);
        final boolean useStartSSL = settings.getAsBoolean(ConfigConstants.ARMOR_AUTHENTICATION_LDAP_LDAPS_STARTTLS_ENABLED, false);
        final LdapConnectionConfig config = new LdapConnectionConfig();

        if (useSSL || useStartSSL) {
            //## Truststore ##
            final KeyStore ts = KeyStore.getInstance(settings.get(ConfigConstants.ARMOR_AUTHENTICATION_LDAP_LDAPS_TRUSTSTORE_TYPE,
                    "JKS"));
            FileInputStream trustStoreFile = new FileInputStream(new File(settings.get(ConfigConstants.ARMOR_AUTHENTICATION_LDAP_LDAPS_TRUSTSTORE_FILEPATH,
                    System.getProperty("java.home") + "/lib/security/cacerts")));
            try {
                ts.load(trustStoreFile, settings.get(ConfigConstants.ARMOR_AUTHENTICATION_LDAP_LDAPS_TRUSTSTORE_PASSWORD, "changeit")
                        .toCharArray());
            } finally {
                trustStoreFile.close();
            }
            final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ts);

            config.setSslProtocol("TLS");
            config.setEnabledCipherSuites(SecurityUtil.getEnabledSslCiphers());
            config.setTrustManagers(tmf.getTrustManagers());
        }

        config.setUseSsl(useSSL);
        config.setUseTls(useStartSSL);
        config.setTimeout(5000L); //5 sec

        final List<String> ldapHosts = settings.getAsList(ConfigConstants.ARMOR_AUTHENTICATION_LDAP_HOST, Arrays.asList("localhost"));

        boolean isValid = false;

        for (String ldapHost : ldapHosts) {
            log.trace("Connect to {}", ldapHost);

            try {

                final String[] split = ldapHost.split(":");

                config.setLdapHost(split[0]);

                if (split.length > 1) {
                    config.setLdapPort(Integer.parseInt(split[1]));
                } else {
                    config.setLdapPort(useSSL ? 636 : 389);
                }

                LdapConnection ldapConnection = new LdapNetworkConnection(config);
                ldapConnection.connect();
                if (!ldapConnection.isConnected()) {
                    continue;
                } else {
                    ldapConnection.close();
                    isValid = true;
                    break;
                }

            } catch (final NumberFormatException e) {
                continue;
            }
        }

        if (!isValid) {
            throw new LdapException("Unable to connect to any of those ldap servers " + ldapHosts.toString());
        }

        DefaultLdapConnectionFactory factory = new DefaultLdapConnectionFactory(config);

        factory.setTimeOut(5000L);

        GenericObjectPool.Config poolConfig = new GenericObjectPool.Config();
        poolConfig.maxActive = settings.getAsInt(ConfigConstants.ARMOR_AUTHENTICATION_LDAP_MAX_ACTIVE_CONNECTIONS, 8);
        ldapConnectionPool = new LdapConnectionPool(new ValidatingPoolableLdapConnectionFactory(factory), poolConfig);

        LdapConnection ldapConnection = ldapConnectionPool.getConnection();

        if (!ldapConnection.isConnected() ) {
            throw new LdapException("Unable to connect to any of those ldap servers " + ldapHosts.toString());
        }

        return ldapConnection;
    }

    public static void releaseConnectionSilently(LdapConnection ldapConnection) {
        if(ldapConnection == null || ldapConnectionPool == null) {
            return;
        }
        try {
            ldapConnectionPool.releaseConnection(ldapConnection);
        } catch (final LdapException ex) {
            log.warn(ex);
        }
    }

//    public static void unbindAndCloseSilently(final LdapConnection connection) {
//        if (connection == null) {
//            return;
//        }
//
//        try {
//            connection.unBind();
//        } catch (final LdapException e) {
//            log.warn(e);
//        }
//
//        try {
//            connection.close();
//        } catch (final IOException e) {
//            log.warn(e);
//        }
//
//    }

    public static String getArmorSessionIdFromCookie(final RestRequest request) {

        final String cookies = request.header("Cookie");

        if (cookies != null) {

            final Set<Cookie> cookiesAsSet = ServerCookieDecoder.STRICT.decode(cookies);

            log.trace("Cookies {}", cookiesAsSet);

            for (final Iterator iterator = cookiesAsSet.iterator(); iterator.hasNext(); ) {
                final Cookie cookie = (Cookie) iterator.next();
                if (ArmorConstants.ARMOR_ES_ARMOR_SESSION.equals(cookie.name())) {
                    return cookie.value();
                }
            }

        }
        return null;
    }

    public static String encryptAndSerializeObject(final Serializable object, final SecretKey key) {

        if (object == null) {
            throw new IllegalArgumentException("object must not be null");
        }

        try {
            final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            final SealedObject sealedobject = new SealedObject(object, cipher);
            final ByteArrayOutputStream bos = new ByteArrayOutputStream();
            final ObjectOutputStream out = new ObjectOutputStream(bos);
            out.writeObject(sealedobject);
            final byte[] bytes = bos.toByteArray();
            return Base64.getEncoder().encodeToString(bytes);
        } catch (final NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            log.error(" error in cryptography configuration", e);
            throw new ElasticsearchException(e);
        } catch (final IOException | IllegalBlockSizeException e){
            log.error(" error during deserialization", e);
            throw new ElasticsearchException(e);
        }
    }

    public static Serializable decryptAnDeserializeObject(final String string, final SecretKey key) {

        if (string == null) {
            throw new IllegalArgumentException("string must not be null");
        }

        try {
            final byte[] userr = Base64.getDecoder().decode(string);
            final ByteArrayInputStream bis = new ByteArrayInputStream(userr);
            final ObjectInputStream in = new ObjectInputStream(bis);
            final SealedObject ud = (SealedObject) in.readObject();
            return (Serializable) ud.getObject(key);
        } catch (final IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeyException e) {
            log.error(e.toString(), e);
            throw new ElasticsearchException(e.toString());
        }
    }


    public static String[] getEnabledSslCiphers(){
        return Arrays.copyOf(ENABLED_SSL_CIPHERS,ENABLED_SSL_CIPHERS.length);
    }

    public static String[] getEnabledSslProtocols(){
        return Arrays.copyOf(ENABLED_SSL_PROTOCOLS,ENABLED_SSL_PROTOCOLS.length);
    }

    private static boolean isWindowsAdmin() {

        try {
            final Class ntSystemClass = Class.forName("com.sun.security.auth.module.NTSystem");
            final Object ntSystem = ntSystemClass.newInstance();
            final String[] groups = (String[]) ntSystemClass.getDeclaredMethod("getGroupIDs").invoke(ntSystem);
            for (final String group : groups) {
                if (group.equals("S-1-5-32-544")) {
                    return true;
                }
            }
            return false;
        } catch (final InstantiationException| IllegalAccessException | IllegalArgumentException | InvocationTargetException |NoSuchMethodException| ClassNotFoundException | SecurityException e) {
            return false;
        }
    }


    public static InetAddress getProxyResolvedHostAddressFromRequest(final RestRequest request, final Settings settings)
            throws UnknownHostException {

        log.debug(request.getClass().toString());

        final String oaddr = ((InetSocketAddress) request.getRemoteAddress()).getHostString();
        log.debug("original hostname: " + oaddr);

        String raddr = oaddr;

        if (oaddr == null || oaddr.isEmpty()) {
            throw new UnknownHostException("Original host is <null> or <empty>");
        }

        final InetAddress iaddr = InetAddress.getByName(oaddr);

        final String xForwardedForHeader = settings.get(ConfigConstants.ARMOR_HTTP_XFORWARDEDFOR_HEADER, "X-Forwarded-For");

        if (xForwardedForHeader != null && !xForwardedForHeader.isEmpty()) {

            final String xForwardedForValue = request.header(xForwardedForHeader);

            log.trace("xForwardedForHeader is " + xForwardedForHeader + ":" + xForwardedForValue);

            final List<String> xForwardedTrustedProxies = settings.getAsList(ConfigConstants.ARMOR_HTTP_XFORWARDEDFOR_TRUSTEDPROXIES);

            final boolean xForwardedEnforce = settings.getAsBoolean(ConfigConstants.ARMOR_HTTP_XFORWARDEDFOR_ENFORCE, false);

            if (xForwardedForValue != null && !xForwardedForValue.isEmpty()) {
                final List<String> addresses = Arrays.asList(xForwardedForValue.replace(" ", "").split(","));
                final List<String> proxiesPassed = new ArrayList<String>(addresses.subList(1, addresses.size()));

                if (xForwardedTrustedProxies.size() == 0) {
                    throw new UnknownHostException("No trusted proxies");
                }

                proxiesPassed.removeAll(xForwardedTrustedProxies);

                log.trace(proxiesPassed.size() + "/" + proxiesPassed);

                if (proxiesPassed.size() == 0 && (xForwardedTrustedProxies.contains(oaddr) || iaddr.isLoopbackAddress())) {

                    raddr = addresses.get(0).trim();

                } else {
                    throw new UnknownHostException("Not all proxies are trusted");
                }

            } else {
                if (xForwardedEnforce) {
                    throw new UnknownHostException("Forward header enforced but not present");
                }
            }

        }

        if (raddr.isEmpty()) {
            throw new UnknownHostException("Host is <null> or <empty>");
        }

        if (raddr.equals(oaddr)) {
            return iaddr;
        } else {
            // if null or "" then loopback is returned
            return InetAddress.getByName(raddr);
        }

    }

    public static void setLdapConnectionPool(LdapConnectionPool ldapConnectionPool) {
        SecurityUtil.ldapConnectionPool = ldapConnectionPool;
    }

}
