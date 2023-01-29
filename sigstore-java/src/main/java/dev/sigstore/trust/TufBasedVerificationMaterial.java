package dev.sigstore.trust;

import dev.sigstore.tuf.MutableTufStore;
import dev.sigstore.tuf.TufStore;
import java.util.List;

/**
 * Extracts Fulcio, and Rekor certificates out of Sigstore TUF.
 * It will replace {@link dev.sigstore.VerificationMaterial} in the future.
 */
public class TufBasedVerificationMaterial implements VerificationMaterial {
  private final TufStore tufStore;

  public TufBasedVerificationMaterial(TufStore tufStore) {
    this.tufStore = tufStore;
  }

  @Override
  public byte[] fulcioCert() {
    throw new UnsupportedOperationException("Not implemented yet");
  }

  @Override
  public List<byte[]> ctfePublicKeys() {
    throw new UnsupportedOperationException("Not implemented yet");
  }

  @Override
  public byte[] rekorPublicKey() {
    throw new UnsupportedOperationException("Not implemented yet");
  }
}
