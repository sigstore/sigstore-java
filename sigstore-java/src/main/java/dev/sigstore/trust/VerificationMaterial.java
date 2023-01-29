package dev.sigstore.trust;

import java.util.List;

public interface VerificationMaterial {
  byte[] fulcioCert();
  List<byte[]> ctfePublicKeys();
  byte[] rekorPublicKey();
}
