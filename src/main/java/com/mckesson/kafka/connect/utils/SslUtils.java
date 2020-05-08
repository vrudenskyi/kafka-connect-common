/**
 * Copyright  Vitalii Rudenskyi (vrudenskyi@gmail.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.mckesson.kafka.connect.utils;

import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.apache.kafka.common.config.AbstractConfig;
import org.apache.kafka.common.config.SslConfigs;
import org.apache.kafka.common.config.types.Password;
import org.apache.kafka.connect.errors.ConnectException;

public class SslUtils {

  public static KeyStore loadKeyStore(String storeType, String storeLoc, Password passwd) throws Exception {

    if (storeLoc == null) {
      return null;
    }
    File f = new File(storeLoc);
    if (!f.getCanonicalPath().equals(storeLoc)) {
      throw new ConnectException("Relative Path not allowed:" + storeLoc);
    }

    final InputStream ksStream = Files.newInputStream(Paths.get(f.getCanonicalPath()));

    if (ksStream == null) {
      throw new ConnectException("Could not load keystore:" + f.getCanonicalPath());
    }
    try (InputStream is = ksStream) {
      KeyStore loadedKeystore = KeyStore.getInstance(storeType);
      loadedKeystore.load(is, passwd.value().toCharArray());
      return loadedKeystore;
    }
  }

  public static SSLContext createSSLContext(AbstractConfig config) throws Exception {

    KeyStore keyStore = SslUtils.loadKeyStore(config.getString(SslConfigs.SSL_KEYSTORE_TYPE_CONFIG),
        config.getString(SslConfigs.SSL_KEYSTORE_LOCATION_CONFIG),
        config.getPassword(SslConfigs.SSL_KEYSTORE_PASSWORD_CONFIG));

    KeyStore trustStore = SslUtils.loadKeyStore(config.getString(SslConfigs.SSL_TRUSTSTORE_TYPE_CONFIG),
        config.getString(SslConfigs.SSL_TRUSTSTORE_LOCATION_CONFIG),
        config.getPassword(SslConfigs.SSL_TRUSTSTORE_PASSWORD_CONFIG));

    SSLContext sslContext;
    if (keyStore != null && trustStore != null) {
      final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
      kmf.init(keyStore, config.getPassword(SslConfigs.SSL_KEY_PASSWORD_CONFIG).value().toCharArray());
      final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
      tmf.init(trustStore);
      sslContext = SSLContext.getInstance(config.getString(SslConfigs.SSL_PROTOCOL_CONFIG));
      sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
    } else {
      sslContext = SSLContext.getDefault();
    }

    return sslContext;
  }

}
