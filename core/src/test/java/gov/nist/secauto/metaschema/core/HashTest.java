/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core;

import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashTest {

  @Test
  void hashTest() throws NoSuchAlgorithmException {
    String[] algorithms = {
        "SHA-224",
        "SHA-256",
        "SHA-384",
        "SHA-512",
        "SHA3-224",
        "SHA3-256",
        "SHA3-384",
        "SHA3-512"
    };

    String text = "The rain in spain falls mostly in the plain.";

    for (String algorithm : algorithms) {
      MessageDigest md = MessageDigest.getInstance(algorithm);
      md.update(text.getBytes());

      byte[] digest = md.digest();

      String hex = bytesToHex(digest);

      System.out.println(algorithm + "(" + hex.length() + "): " + hex);
    }
  }

  private static String bytesToHex(byte[] bytes) {
    StringBuilder sb = new StringBuilder();
    for (byte b : bytes) {
      sb.append(String.format("%02x", b));
    }
    return sb.toString();
  }
}
