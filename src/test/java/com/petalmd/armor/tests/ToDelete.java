package com.petalmd.armor.tests;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by jehuty0shift on 06/04/18.
 */
public class ToDelete {


    public static void main(String[] args) {


        try {

            KeyStore keyStore = KeyStore.getInstance("JKS");
            FileInputStream is = new FileInputStream("/media/disk1/Trash/server.truststore.jks");
            keyStore.load(is, "dev2113".toCharArray());
            is.close();


            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
            keyManagerFactory.init(keyStore, "dev2113".toCharArray());

            System.setProperty("https.protocols", "TLSv1,TLSV1.1,TLSV1.2");

            TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                            return new X509Certificate[0];
                        }

                        public void checkClientTrusted(
                                java.security.cert.X509Certificate[] certs, String authType) {
                        }

                        public void checkServerTrusted(
                                java.security.cert.X509Certificate[] certs, String authType) {
                        }
                    }
            };


            SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
            sslContext.init(keyManagerFactory.getKeyManagers(), trustAllCerts, new java.security.SecureRandom());
            SSLContext.setDefault(sslContext);

            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();

            List<SSLSocket> socketList = new ArrayList<>();

            for (int i = 0 ; i < 100; i++) {
                SSLSocket socket =
                        (SSLSocket) factory.createSocket("127.0.0.1", 6514);

                socket.setEnabledProtocols(new String[]{"TLSv1.1", "TLSv1.2"});
                socket.setEnabledCipherSuites(socket.getSupportedCipherSuites());
                socket.startHandshake();

                System.out.println("Handshake successfull");

                socketList.add(socket);
                Thread.sleep(50);

            }

            for (SSLSocket socket : socketList) {
                socket.close();
            }

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("failure");
        }

    }


}
